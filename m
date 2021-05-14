Return-Path: <kasan-dev+bncBCGJZ5PL74JRB4M27CCAMGQEIMGGNMI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ed1-x53a.google.com (mail-ed1-x53a.google.com [IPv6:2a00:1450:4864:20::53a])
	by mail.lfdr.de (Postfix) with ESMTPS id 60800380372
	for <lists+kasan-dev@lfdr.de>; Fri, 14 May 2021 07:41:06 +0200 (CEST)
Received: by mail-ed1-x53a.google.com with SMTP id i3-20020aa7dd030000b029038ce772ffe4sf1417515edv.12
        for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 22:41:06 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620970866; cv=pass;
        d=google.com; s=arc-20160816;
        b=WEpWS2PfqKnIu73FLqih/tZAoi7WRR8By1TCb87VZiCCEsF4l1QNThVOYSYtDBP/2H
         we6xxagh3DR7oPbLafnUQYTnIFB8YykhCTPWGhGPGi4jWmXwO93rj/kkD8i6Qlzc+ggA
         T8Wubv7N3W7Wgl/NHoaPCAUVKJaLxiD1KlnYRsaFwjRELj+Y8FjyzGOAPDaAav9HnNh2
         pQRqmF8nJpVefr70EArn7hEOvzRQQsord6GIdR09OjkJ7q4WtHRMPKlfoAbm4GiHHrdo
         psdIFqinfElsosfFyOzY+Kdfs15eCCuGr6zzTd1wBzNYsYcM9AnGjk8THD9+P4IN4ghZ
         /V+A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:from:references:cc:to
         :subject:sender:dkim-signature;
        bh=oB7uzMlE3qKnXFxYujQuzmeGee1DNCAfq4GYSnlW8Ts=;
        b=N3AOCBcdmSGIo3Bxp5+P+ryl77d7op9Cg3eVzNlShcLlHfQ0/9Mn0y8uAJe+cX7guF
         +VCtyr6cJPlcjdNT/aI7su+9pnE6+d/R9NWU2gNly5lExbFdIQKdq/47sQg+3ppUAucT
         +NG/LoPWjtekNI8lOPSf6OcVeJFneLo/COemCyzTn1Oxi+3XJNYy9s2LCgSHdD/GBNRK
         wYIG0rLCC3fGt05gNB0SSwpXN3uCIaLQhWWou94o/5limMctTTGf51qMqR1fGHtPR9jf
         2lfAtP87Vy1LFf5Ch4ArfB07WZjNKUS8/hrt/7gLK6ZSfKYe10mnXEAVxWk5MF21u+Cd
         zzhA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=GWH4txmB;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=manfred@colorfullife.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:subject:to:cc:references:from:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=oB7uzMlE3qKnXFxYujQuzmeGee1DNCAfq4GYSnlW8Ts=;
        b=LPFa5Lan9yBPvXucJk6ip02C8DLJUpsOQoRV8/gtYZt8mc50aK14FqV2jJHBoiBOEI
         EkdG0KwKcsbvgFUp7QSQQ5P4Tey4koWwikj6grGiB/FaowRm8HwPIFPr9C/0ieTeKbQY
         CVJrE5tPpL5TyjbW8tEu9OD4jcL6MEOAmcuVqqa2xkbsRBsiaHE6zVOoYRvD8nWVIvHH
         QHuuJkjgxPGhjxbwoptyEEJ1rHvlMvOwFDrzjIXcczlWbdmq69RtnuqMfAAC8sbR44b5
         ByfSOtEBpwyzkgnWIKEQwcgj1ZQw5LvHa5con6JeS85watkm2aqNtmsHJW1HxT+e36aK
         mhBA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:subject:to:cc:references:from:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=oB7uzMlE3qKnXFxYujQuzmeGee1DNCAfq4GYSnlW8Ts=;
        b=q7vmN9mkNaqvAdc+z5PDOrGRGDYZi6z25F975Yq3eCaFfwfWeQforaRtjJ6qycgetZ
         N5zpcNto3S/llTQReQvxVtGge90CA7rSUpYXruBNiGPxYVXzEAq/K6Oj7bjkb47x5go6
         yFMM7hyb+SrAvO7HDGGrn25ha5Fmnih/VKxhOBg39kDTlkWu7jW4bvL2JNqyLeNkJGNx
         UzcpxgsBMfXqVIo5pyDf89JMmDc25k5i0eoSapsarkgCdy5pUJETg1pD4VGW1fqPn40U
         o5zhpwhC9Z1jFM6ii79jOOSrxuG/C9uJUeOsJyqL4Cqtp6HoT1icfB3gYx3csF7bl2lC
         MM+Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530Frtl79J1VHYLv2GhhD/ZO8y5IW7KDM8qckjdjk2/iIVY9uA9d
	yVIBHR5oWR+FUw04qkwmtsg=
X-Google-Smtp-Source: ABdhPJzyQPUKs+XeFXPOGhvRmzW7IDrMT5MSU5fEXxcOs/BChttofu5pvB4m6sx4i8Us0MWkFvZ+1w==
X-Received: by 2002:a17:907:8323:: with SMTP id mq35mr47214862ejc.391.1620970866160;
        Thu, 13 May 2021 22:41:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:906:7c45:: with SMTP id g5ls1488131ejp.5.gmail; Thu, 13
 May 2021 22:41:05 -0700 (PDT)
X-Received: by 2002:a17:906:711a:: with SMTP id x26mr46584543ejj.125.1620970865322;
        Thu, 13 May 2021 22:41:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620970865; cv=none;
        d=google.com; s=arc-20160816;
        b=0crINPW04VY79U0dk60cGFNktLr3slKXPxJ5WL4plcfsp/HwDffpErLfCCM30v9CdU
         ryKNGDbAYmHWNV8ixMvCTIc0o/8Wqb0wb1PNlc7PIwXwhliKl9DXuH1/sR9F0oiRJ/xA
         +l6NeVR/8RLcuh5jdnCTO1JYUcDIHEMvW3KBr7TsmV8wXRipfxDiV7mH7E+lzn79wEJz
         w62BY2VP0yiSq+ZamI+lhqmnckE/XygmRWGdXNWWLgwATMQ8kbmu4B31PvIskbYZigvZ
         6maedNA3yLseS+hO+dknLBJD7WAeQTHHsGubebIXgcnLMn/r5EgKrCfp+FaDfYouqteS
         Zsgw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:from:references:cc:to:subject:dkim-signature;
        bh=vld0EM5Td8QSdtllG27OwpywTviitekSHv+GerNoer8=;
        b=fYK8NOrNN2wBEwhdPddW6SW2gh1owZ51xAQj8HiFRj0R3s2+WUv8PqS9U03l5tL4Vd
         IUHMzn0Xmn/SyGPMwKkBbFhr9yVRs0tnb2WevQ4es/FhS+G5kVadGIlwGkibUXUKTk9L
         OG/QqxRaKvm/lijRLMlGHp6Bqs7PC+UOxUJ0RBgFPrRu0x/FjyETfHw9hvKuvpVfkulz
         HV5IMPCcZgdhe3RiXGS2HfQSPz+bsYl12cKvWbgEG4TDipSteKFtJokaxTs/77jM/t1i
         7YtxhiOzNCX43XE7Vwi/NJOUv8Uktcz3ndBkhq+2Jd8Twj4SW4BpzuBIisdUl4G1gCdn
         En9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=GWH4txmB;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=manfred@colorfullife.com
Received: from mail-ed1-x52a.google.com (mail-ed1-x52a.google.com. [2a00:1450:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id di23si197262edb.0.2021.05.13.22.41.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 May 2021 22:41:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::52a as permitted sender) client-ip=2a00:1450:4864:20::52a;
Received: by mail-ed1-x52a.google.com with SMTP id g14so33412861edy.6
        for <kasan-dev@googlegroups.com>; Thu, 13 May 2021 22:41:05 -0700 (PDT)
X-Received: by 2002:a05:6402:2714:: with SMTP id y20mr53569437edd.348.1620970864803;
        Thu, 13 May 2021 22:41:04 -0700 (PDT)
Received: from localhost.localdomain (p200300d9970469005bb43495a574ac97.dip0.t-ipconnect.de. [2003:d9:9704:6900:5bb4:3495:a574:ac97])
        by smtp.googlemail.com with ESMTPSA id h9sm3786499ede.93.2021.05.13.22.41.03
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 13 May 2021 22:41:03 -0700 (PDT)
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
To: paulmck@kernel.org
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
 <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
 <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
From: Manfred Spraul <manfred@colorfullife.com>
Message-ID: <9c9739ec-1273-5137-7b6d-00a27a22ffca@colorfullife.com>
Date: Fri, 14 May 2021 07:41:02 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
In-Reply-To: <20210513190201.GE975577@paulmck-ThinkPad-P17-Gen-1>
Content-Type: multipart/mixed;
 boundary="------------894E4A7E2BB24AC19EC6B0F5"
Content-Language: en-US
X-Original-Sender: manfred@colorfullife.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623
 header.b=GWH4txmB;       spf=pass (google.com: domain of manfred@colorfullife.com
 designates 2a00:1450:4864:20::52a as permitted sender) smtp.mailfrom=manfred@colorfullife.com
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

This is a multi-part message in MIME format.
--------------894E4A7E2BB24AC19EC6B0F5
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable

On 5/13/21 9:02 PM, Paul E. McKenney wrote:
> On Thu, May 13, 2021 at 08:10:51AM +0200, Manfred Spraul wrote:
>> Hi Paul,
>>
>> On 5/12/21 10:17 PM, Paul E. McKenney wrote:
>> [...]
>>> 	int foo;
>>> 	DEFINE_RWLOCK(foo_rwlock);
>>>
>>> 	void update_foo(int newval)
>>> 	{
>>> 		write_lock(&foo_rwlock);
>>> 		foo =3D newval;
>>> 		do_something(newval);
>>> 		write_unlock(&foo_rwlock);
>>> 	}
>>>
>>> 	int read_foo(void)
>>> 	{
>>> 		int ret;
>>>
>>> 		read_lock(&foo_rwlock);
>>> 		do_something_else();
>>> 		ret =3D foo;
>>> 		read_unlock(&foo_rwlock);
>>> 		return ret;
>>> 	}
>>>
>>> 	int read_foo_diagnostic(void)
>>> 	{
>>> 		return data_race(foo);
>>> 	}
>> The text didn't help, the example has helped:
>>
>> It was not clear to me if I have to use data_race() both on the read and=
 the
>> write side, or only on one side.
>>
>> Based on this example: plain C may be paired with data_race(), there is =
no
>> need to mark both sides.
> Actually, you just demonstrated that this example is quite misleading.
> That data_race() works only because the read is for diagnostic
> purposes.  I am queuing a commit with your Reported-by that makes
> read_foo_diagnostic() just do a pr_info(), like this:
>
> 	void read_foo_diagnostic(void)
> 	{
> 		pr_info("Current value of foo: %d\n", data_race(foo));
> 	}
>
> So thank you for that!

I would not like this change at all.
Assume you chase a rare bug, and notice an odd pr_info() output.
It will take you really long until you figure out that a data_race()=20
mislead you.
Thus for a pr_info(), I would consider READ_ONCE() as the correct thing.

What about something like the attached change?

--

 =C2=A0=C2=A0=C2=A0 Manfred


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/9c9739ec-1273-5137-7b6d-00a27a22ffca%40colorfullife.com.

--------------894E4A7E2BB24AC19EC6B0F5
Content-Type: text/plain; charset=UTF-8;
 name="access-marking.txt"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="access-marking.txt"

ZGlmZiAtLWdpdCBhL3Rvb2xzL21lbW9yeS1tb2RlbC9Eb2N1bWVudGF0aW9uL2FjY2Vzcy1t
YXJraW5nLnR4dCBiL3Rvb2xzL21lbW9yeS1tb2RlbC9Eb2N1bWVudGF0aW9uL2FjY2Vzcy1t
YXJraW5nLnR4dAppbmRleCAxYWIxODlmNTFmNTUuLjU4ODMyNmI2MDgzNCAxMDA2NDQKLS0t
IGEvdG9vbHMvbWVtb3J5LW1vZGVsL0RvY3VtZW50YXRpb24vYWNjZXNzLW1hcmtpbmcudHh0
CisrKyBiL3Rvb2xzL21lbW9yeS1tb2RlbC9Eb2N1bWVudGF0aW9uL2FjY2Vzcy1tYXJraW5n
LnR4dApAQCAtNjgsNiArNjgsMTEgQEAgUkVBRF9PTkNFKCkgYW5kIFdSSVRFX09OQ0UoKToK
IAogNC4JV3JpdGVzIHNldHRpbmcgdmFsdWVzIHRoYXQgZmVlZCBpbnRvIGVycm9yLXRvbGVy
YW50IGhldXJpc3RpY3MuCiAKK0luIHRoZW9yeSwgcGxhaW4gQy1sYW5ndWFnZSBsb2FkcyBj
YW4gYWxzbyBiZSB1c2VkIGZvciB0aGVzZSB1c2UgY2FzZXMuCitIb3dldmVyLCBpbiBwcmFj
dGljZSB0aGlzIHdpbGwgaGF2ZSB0aGUgZGlzYWR2YW50YWdlIG9mIGNhdXNpbmcgS0NTQU4K
K3RvIGdlbmVyYXRlIGZhbHNlIHBvc2l0aXZlcyBiZWNhdXNlIEtDU0FOIHdpbGwgaGF2ZSBu
byB3YXkgb2Yga25vd2luZwordGhhdCB0aGUgcmVzdWx0aW5nIGRhdGEgcmFjZSB3YXMgaW50
ZW50aW9uYWwuCisKIAogRGF0YS1SYWN5IFJlYWRzIGZvciBBcHByb3hpbWF0ZSBEaWFnbm9z
dGljcwogCkBAIC04NiwxMSArOTEsNiBAQCB0aGF0IGZhaWwgdG8gZXhjbHVkZSB0aGUgdXBk
YXRlcy4gIEluIHRoaXMgY2FzZSwgaXQgaXMgaW1wb3J0YW50IHRvIHVzZQogZGF0YV9yYWNl
KCkgZm9yIHRoZSBkaWFnbm9zdGljIHJlYWRzIGJlY2F1c2Ugb3RoZXJ3aXNlIEtDU0FOIHdv
dWxkIGdpdmUKIGZhbHNlLXBvc2l0aXZlIHdhcm5pbmdzIGFib3V0IHRoZXNlIGRpYWdub3N0
aWMgcmVhZHMuCiAKLUluIHRoZW9yeSwgcGxhaW4gQy1sYW5ndWFnZSBsb2FkcyBjYW4gYWxz
byBiZSB1c2VkIGZvciB0aGlzIHVzZSBjYXNlLgotSG93ZXZlciwgaW4gcHJhY3RpY2UgdGhp
cyB3aWxsIGhhdmUgdGhlIGRpc2FkdmFudGFnZSBvZiBjYXVzaW5nIEtDU0FOCi10byBnZW5l
cmF0ZSBmYWxzZSBwb3NpdGl2ZXMgYmVjYXVzZSBLQ1NBTiB3aWxsIGhhdmUgbm8gd2F5IG9m
IGtub3dpbmcKLXRoYXQgdGhlIHJlc3VsdGluZyBkYXRhIHJhY2Ugd2FzIGludGVudGlvbmFs
LgotCiAKIERhdGEtUmFjeSBSZWFkcyBUaGF0IEFyZSBDaGVja2VkIEFnYWluc3QgTWFya2Vk
IFJlbG9hZAogCkBAIC0xMTAsMTEgKzExMCw2IEBAIHRoYXQgcHJvdmlkZXMgdGhlIGNvbXBp
bGVyIG11Y2ggbGVzcyBzY29wZSBmb3IgbWlzY2hpZXZvdXMgb3B0aW1pemF0aW9ucy4KIENh
cHR1cmluZyB0aGUgcmV0dXJuIHZhbHVlIGZyb20gY21weGNoZygpIGFsc28gc2F2ZXMgYSBt
ZW1vcnkgcmVmZXJlbmNlCiBpbiBtYW55IGNhc2VzLgogCi1JbiB0aGVvcnksIHBsYWluIEMt
bGFuZ3VhZ2UgbG9hZHMgY2FuIGFsc28gYmUgdXNlZCBmb3IgdGhpcyB1c2UgY2FzZS4KLUhv
d2V2ZXIsIGluIHByYWN0aWNlIHRoaXMgd2lsbCBoYXZlIHRoZSBkaXNhZHZhbnRhZ2Ugb2Yg
Y2F1c2luZyBLQ1NBTgotdG8gZ2VuZXJhdGUgZmFsc2UgcG9zaXRpdmVzIGJlY2F1c2UgS0NT
QU4gd2lsbCBoYXZlIG5vIHdheSBvZiBrbm93aW5nCi10aGF0IHRoZSByZXN1bHRpbmcgZGF0
YSByYWNlIHdhcyBpbnRlbnRpb25hbC4KLQogCiBSZWFkcyBGZWVkaW5nIEludG8gRXJyb3It
VG9sZXJhbnQgSGV1cmlzdGljcwogCkBAIC0xMjUsMTEgKzEyMCw5IEBAIHRoYXQgZGF0YV9y
YWNlKCkgbG9hZHMgYXJlIHN1YmplY3QgdG8gbG9hZCBmdXNpbmcsIHdoaWNoIGNhbiByZXN1
bHQgaW4KIGNvbnNpc3RlbnQgZXJyb3JzLCB3aGljaCBpbiB0dXJuIGFyZSBxdWl0ZSBjYXBh
YmxlIG9mIGJyZWFraW5nIGhldXJpc3RpY3MuCiBUaGVyZWZvcmUgdXNlIG9mIGRhdGFfcmFj
ZSgpIHNob3VsZCBiZSBsaW1pdGVkIHRvIGNhc2VzIHdoZXJlIHNvbWUgb3RoZXIKIGNvZGUg
KHN1Y2ggYXMgYSBiYXJyaWVyKCkgY2FsbCkgd2lsbCBmb3JjZSB0aGUgb2NjYXNpb25hbCBy
ZWxvYWQuCi0KLUluIHRoZW9yeSwgcGxhaW4gQy1sYW5ndWFnZSBsb2FkcyBjYW4gYWxzbyBi
ZSB1c2VkIGZvciB0aGlzIHVzZSBjYXNlLgotSG93ZXZlciwgaW4gcHJhY3RpY2UgdGhpcyB3
aWxsIGhhdmUgdGhlIGRpc2FkdmFudGFnZSBvZiBjYXVzaW5nIEtDU0FOCi10byBnZW5lcmF0
ZSBmYWxzZSBwb3NpdGl2ZXMgYmVjYXVzZSBLQ1NBTiB3aWxsIGhhdmUgbm8gd2F5IG9mIGtu
b3dpbmcKLXRoYXQgdGhlIHJlc3VsdGluZyBkYXRhIHJhY2Ugd2FzIGludGVudGlvbmFsLgor
VGhlIGhldXJpc3RpY3MgbXVzdCBiZSBhYmxlIHRvIGhhbmRsZSBhbnkgZXJyb3IuIElmIHRo
ZSBoZXVyaXN0aWNzIGFyZQorb25seSBhYmxlIHRvIGhhbmRsZSBvbGQgYW5kIG5ldyB2YWx1
ZXMsIHRoZW4gV1JJVEVfT05DRSgpL1JFQURfT05DRSgpCittdXN0IGJlIHVzZWQuCiAKIAog
V3JpdGVzIFNldHRpbmcgVmFsdWVzIEZlZWRpbmcgSW50byBFcnJvci1Ub2xlcmFudCBIZXVy
aXN0aWNzCkBAIC0xNDIsMTEgKzEzNSw4IEBAIGR1ZSB0byBjb21waWxlci1tYW5nbGVkIHJl
YWRzLCBpdCBjYW4gYWxzbyB0b2xlcmF0ZSB0aGUgb2NjYXNpb25hbAogY29tcGlsZXItbWFu
Z2xlZCB3cml0ZSwgYXQgbGVhc3QgYXNzdW1pbmcgdGhhdCB0aGUgcHJvcGVyIHZhbHVlIGlz
IGluCiBwbGFjZSBvbmNlIHRoZSB3cml0ZSBjb21wbGV0ZXMuCiAKLVBsYWluIEMtbGFuZ3Vh
Z2Ugc3RvcmVzIGNhbiBhbHNvIGJlIHVzZWQgZm9yIHRoaXMgdXNlIGNhc2UuICBIb3dldmVy
LAotaW4ga2VybmVscyBidWlsdCB3aXRoIENPTkZJR19LQ1NBTl9BU1NVTUVfUExBSU5fV1JJ
VEVTX0FUT01JQz1uLCB0aGlzCi13aWxsIGhhdmUgdGhlIGRpc2FkdmFudGFnZSBvZiBjYXVz
aW5nIEtDU0FOIHRvIGdlbmVyYXRlIGZhbHNlIHBvc2l0aXZlcwotYmVjYXVzZSBLQ1NBTiB3
aWxsIGhhdmUgbm8gd2F5IG9mIGtub3dpbmcgdGhhdCB0aGUgcmVzdWx0aW5nIGRhdGEgcmFj
ZQotd2FzIGludGVudGlvbmFsLgorTm90ZSB0aGF0IEtDU0FOIHdpbGwgb25seSBkZXRlY3Qg
bWFuZ2xlZCB3cml0ZXMgaW4ga2VybmVscyBidWlsdCB3aXRoCitDT05GSUdfS0NTQU5fQVNT
VU1FX1BMQUlOX1dSSVRFU19BVE9NSUM9bi4KIAogCiBVc2Ugb2YgUGxhaW4gQy1MYW5ndWFn
ZSBBY2Nlc3Nlcwo=
--------------894E4A7E2BB24AC19EC6B0F5--
