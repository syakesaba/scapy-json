#!/usr/bin/env python
# encoding: utf-8

from scapy.packet import Packet
import json

class JsonPacket(Packet):
    name = "JsonPacket"
    fields_desc = []
    json_valid_types = (dict,list,unicode,str,int,long,float,bool,None)

    #Override
    def build_done(self,pkt):
        jsonized = self._jsonize_packet(pkt)
        return json.dumps(jsonized, ensure_ascii=False, encoding="utf-8", indent=4)

    def _jsonize_packet(self, pkt):
        out = []
        for layer in self._walk_layers(pkt):
            layer_name = layer.name if layer.name else layer.__name__
            out.append({layer_name:self._serialize_fields(layer,{})})
        return out

    def _walk_layers(self, pkt):
        i=1
        layer = self.getlayer(i)
        while layer:
            yield layer
            i += 1
            layer = self.getlayer(i)

    def _serialize_fields(self, layer, serialized_fields={}):
        if hasattr(layer, "fields_desc"):
            for field in layer.fields_desc:
                self._extract_fields(layer, field, serialized_fields)
        return serialized_fields

    def _extract_fields(self, layer, field, extracted={}):
        value = layer.__getattr__(field.name)
        if type(value) in self.json_valid_types and \
                not hasattr(value, "fields_desc") and \
                    not type(value) == list:
            extracted.update({field.name:value})
        else:
            local_serialized = {}
            extracted.update({field.name:local_serialized})
            self._serialize_fields(field, local_serialized)

if __name__ == "__main__":
    from scapy.main import interact
    from scapy.all import *
    #TEST
    try:
        sniff(prn=lambda p:JsonPacket()/p,lfilter=lambda p:TCP in p and p.dport == 80)
    except Exception as e:
        print e
    interact(mydict=locals())
