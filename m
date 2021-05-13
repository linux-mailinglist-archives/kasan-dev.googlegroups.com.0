Return-Path: <kasan-dev+bncBCGJZ5PL74JRB34F6OCAMGQE3XWLKUQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13f.google.com (mail-lf1-x13f.google.com [IPv6:2a00:1450:4864:20::13f])
	by mail.lfdr.de (Postfix) with ESMTPS id E62C837F2D5
	for <lists+kasan-dev@lfdr.de>; Thu, 13 May 2021 08:10:55 +0200 (CEST)
Received: by mail-lf1-x13f.google.com with SMTP id l27-20020a056512333bb02901d2b8c62620sf5445865lfe.8
        for <lists+kasan-dev@lfdr.de>; Wed, 12 May 2021 23:10:55 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620886255; cv=pass;
        d=google.com; s=arc-20160816;
        b=FbQwl/Y082TXTuxhrgYYkh4n3uEt7/nbAZ3GkntwAX6tWWUuip5/plwD2jYSW1mJCe
         QRMhADzXhOyAR/Q/CLM83mS84XhE5pVs7QMFJ1GPsGTFu9BtLNoUn+mt0NXEe848Fxhf
         EjuIW1DMpEQVswVZrEBw0sscdXYqvc4LVrb4XbJy7zjpAOXOfoBQBCIf6f7QyHUdgPnr
         Yb3fOMaLyN9+ujxk44vvBFcZtrQJd+dywB7hKOE/4crJ1s8QXHVkXIQCUQfSHtaL+UTb
         347GaK8G8lgkfxl7Zt0c8ADRV0AXilTeQeWGCal++aoDNUVSFN+ea/ipApfTl9vV49j5
         wtWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:references:cc:to:subject
         :from:sender:dkim-signature;
        bh=L/ekzcSMYDyCIyNHwv99XcqflHSKs3oEssgSnjWA75M=;
        b=hPz3nhG6ElZI+TkCLbGxNzcHJX0kjg3vm2bwbbmx3N2YLDGDBLf/Yd5hYHvTbNv1Mt
         GKSlXOI824kqVYjTATD98ePmTVhQiDF2gRmaajlERhA9HQgQvHHMvCg6HdxobVK5/I7u
         qI01MoiK/UVup34BSvwN6Z5RoUTFcPftRi1b2O9qsdAGjkLKCYWMwHdGjosoRO1hFMrE
         dec465/oHuSD4xutuuopgU7MReZ2/1hZVWe/hzSCu1qdH3IrIjBugrLzV8HXKK0Giitr
         E3G4kG+GRyA7ekgRE547g+hN7B4UNgCEaeHlMgWSvSDsrC0MqDD1tTzYpIojkAAGq+nz
         lGIg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=VW0M74vS;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=manfred@colorfullife.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:subject:to:cc:references:message-id:date:user-agent
         :mime-version:in-reply-to:content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=L/ekzcSMYDyCIyNHwv99XcqflHSKs3oEssgSnjWA75M=;
        b=hNYq+hPZbgkrArswQTmVKCyFpZXf+3OkxtC5ofeNxbbJHl/uJwGdTDiLJFvyMHEXTe
         GpCWFlkBikLDYsilt6Y4JEF/puCHNE5XMRPhtFmNdWy3wOjpWs9KN9doVdXPWNn1cFmX
         0bGjcFsuLnCgEGvGMteXH4n6G+Tnq5RqhbSx2x7DBFf3P3LjJYvMldb9Jo1R7Bh0pxje
         9JlUcjbYXDMkocedblYhLnZfZluCKiZCxhLryV2bP7HK83z/H3YYLy5CR/xd3TEEhKCi
         yaa3FvZ429GN8m5BK3jM7mJURrR3ovkAdzfu3y0ymoiFGSP/6lUuF7lED2hhDvog1iyH
         Bq7w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:subject:to:cc:references:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=L/ekzcSMYDyCIyNHwv99XcqflHSKs3oEssgSnjWA75M=;
        b=XANO1FCtbJy8H2G3poJzoMzcQgp/fBRs7YcgcrFI+ksEq40Lx9KiwzVFZGxCPakT8k
         UxpnIIextW1bcYLp5bfE1CjssUnPN6o6snXT9JqJTZyy7B8pVzqoLo8TZ71PNmT3Ei8c
         JtnVnak6FlmxHr9hOJL3Rm1gmmZGF5MxZjeqdYnbIFOWzqa9OaY1YB1CgrnPtIRB5tD2
         qwDW5pn1ySY2DN79+6hGwutJxuF7736wNs8GGuPUO0qJx5c13tgjodF0/dxUqe9M3cHf
         twC5qk+MwODmink0q93Q8KNgFV0M0rjtI7INjNDTi1YFZ2rHiObenxpzRndGWlIXh8tV
         Pz6w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531D60WsWdVPA84XTR8q+7SOhVAbzRKzX5amv2YWr4fPdBxI1FV8
	LFWtV04ux9lbZtznjXsHc5M=
X-Google-Smtp-Source: ABdhPJy0B8DfUBKcGiqIDoN5Gw6h6M+Xl6Nf6ZFcvKEVHuZ4l+RCKElVPlTgOu44I06BO8l9+HAeXg==
X-Received: by 2002:a2e:4809:: with SMTP id v9mr21667413lja.496.1620886255379;
        Wed, 12 May 2021 23:10:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:a36f:: with SMTP id i15ls860715ljn.11.gmail; Wed, 12 May
 2021 23:10:54 -0700 (PDT)
X-Received: by 2002:a05:651c:210e:: with SMTP id a14mr16616444ljq.156.1620886254208;
        Wed, 12 May 2021 23:10:54 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620886254; cv=none;
        d=google.com; s=arc-20160816;
        b=Gb/AYvMZsA0vVjhgUNyALKMql777HLKSccKY2O3lmWOH7gYv+JxIqs6+BUKHmfNDjP
         rW2PFMK9Rtj/prO9vDYxO6MBdZMiBCV2Wlk+pTthCfAEtKKbTVVlBLzq7MHi75hOoIzp
         YotlgeRt9jqltXKabPVbYpRtWTCdQDlSzUDjyicVE8bF6GXR5tlH68UHBjS+q8mK7hd+
         Mrc8nO7kfF1JVxiqnI/+EhwHphfq212hC3y1KzxRzrn8pRUUzEoGA49vHzv3KbmqvJ2u
         gagxvH2z8Cm1AfwEqTTYKU2lWgAmDDukqzSMDKWNiC+p23UJCRUSNlK0hnakp7KwsbMn
         Se2w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-language:in-reply-to:mime-version:user-agent:date
         :message-id:references:cc:to:subject:from:dkim-signature;
        bh=Iym9nl8hxVptAjnCNKSYtBku3Ry55aXWZ53H7Q29L9o=;
        b=AJazmzpFobCjHoreGyrDlbbHM7+94xMqO6TqeHi9w/9ojtaW7B8kTa1zkStd8lC/S8
         J/piicJKW+i+2x4rHe07yw/dI8VRZe1bJo4wyzo9q+YVXSKiWpQ4PsSPLRPNqwmI02Zz
         og229tyg//sOFaxh7sH71QzMYQKC7/N5u70Qi+GvQe26zrqbHwFKSo2CXiDhQIR9K+Gy
         Hm3TUr4rkTBUjqpi1wMqLt5+pPy1eOI+tWaqCil8ioax4J6K/AelRqDFs5VNh0n9luy6
         l8nJ9p6OsW6VCvOGj3Sr5Suv88PiIMFPen9tidhg9YPig0b0lWhpxYacp1+F55AamgSO
         lFMQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623 header.b=VW0M74vS;
       spf=pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=manfred@colorfullife.com
Received: from mail-wm1-x330.google.com (mail-wm1-x330.google.com. [2a00:1450:4864:20::330])
        by gmr-mx.google.com with ESMTPS id i14si80747ljg.7.2021.05.12.23.10.54
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 May 2021 23:10:54 -0700 (PDT)
Received-SPF: pass (google.com: domain of manfred@colorfullife.com designates 2a00:1450:4864:20::330 as permitted sender) client-ip=2a00:1450:4864:20::330;
Received: by mail-wm1-x330.google.com with SMTP id o127so14017401wmo.4
        for <kasan-dev@googlegroups.com>; Wed, 12 May 2021 23:10:54 -0700 (PDT)
X-Received: by 2002:a1c:48e:: with SMTP id 136mr1736040wme.166.1620886253676;
        Wed, 12 May 2021 23:10:53 -0700 (PDT)
Received: from localhost.localdomain (p200300d9970517000139f30f0798d643.dip0.t-ipconnect.de. [2003:d9:9705:1700:139:f30f:798:d643])
        by smtp.googlemail.com with ESMTPSA id 15sm1440857wmj.28.2021.05.12.23.10.52
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 12 May 2021 23:10:52 -0700 (PDT)
From: Manfred Spraul <manfred@colorfullife.com>
Subject: Re: ipc/sem, ipc/msg, ipc/mqueue.c kcsan questions
To: paulmck@kernel.org
Cc: kasan-dev <kasan-dev@googlegroups.com>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 Davidlohr Bueso <dbueso@suse.de>, 1vier1@web.de
References: <a9b36c77-dc42-4ab2-9740-f27b191dd403@colorfullife.com>
 <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
Message-ID: <343390da-2307-442e-8073-d1e779c85eeb@colorfullife.com>
Date: Thu, 13 May 2021 08:10:51 +0200
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101
 Thunderbird/78.10.1
MIME-Version: 1.0
In-Reply-To: <20210512201743.GW975577@paulmck-ThinkPad-P17-Gen-1>
Content-Type: multipart/mixed;
 boundary="------------7E09A4E938C7783C55499CA3"
Content-Language: en-US
X-Original-Sender: manfred@colorfullife.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@colorfullife-com.20150623.gappssmtp.com header.s=20150623
 header.b=VW0M74vS;       spf=pass (google.com: domain of manfred@colorfullife.com
 designates 2a00:1450:4864:20::330 as permitted sender) smtp.mailfrom=manfred@colorfullife.com
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
--------------7E09A4E938C7783C55499CA3
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable

Hi Paul,

On 5/12/21 10:17 PM, Paul E. McKenney wrote:
> On Wed, May 12, 2021 at 09:58:18PM +0200, Manfred Spraul wrote:
>> [...]
>> sma->use_global_lock is evaluated in sem_lock() twice:
>>
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /*
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * Initial check for u=
se_global_lock. Just an optimization,
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 * no locking, no memo=
ry barrier.
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 */
>>>  =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 if (!sma->use_global_lock) =
{
>> Both sides of the if-clause handle possible data races.
>>
>> Is
>>
>>  =C2=A0=C2=A0=C2=A0 if (!data_race(sma->use_global_lock)) {
>>
>> the correct thing to suppress the warning?
> Most likely READ_ONCE() rather than data_race(), but please see
> the end of this message.

Based on the document, I would say data_race() is sufficient:

I have replaced the code with "if (jiffies %2)", and it runs fine.

Thus I don't see which evil things a compiler could do, ... .

[...]

Does tools/memory-model/Documentation/access-marking.txt, shown below,
> help?
>
[...]
> 	int foo;
> 	DEFINE_RWLOCK(foo_rwlock);
>
> 	void update_foo(int newval)
> 	{
> 		write_lock(&foo_rwlock);
> 		foo =3D newval;
> 		do_something(newval);
> 		write_unlock(&foo_rwlock);
> 	}
>
> 	int read_foo(void)
> 	{
> 		int ret;
>
> 		read_lock(&foo_rwlock);
> 		do_something_else();
> 		ret =3D foo;
> 		read_unlock(&foo_rwlock);
> 		return ret;
> 	}
>
> 	int read_foo_diagnostic(void)
> 	{
> 		return data_race(foo);
> 	}

The text didn't help, the example has helped:

It was not clear to me if I have to use data_race() both on the read and=20
the write side, or only on one side.

Based on this example: plain C may be paired with data_race(), there is=20
no need to mark both sides.


Attached is a dummy change to ipc/sem.c, where I have added comments to=20
every access.

If data_race() is sufficient, then I think I have understood the rules,=20
and I would recheck ipc/*.c and the netfilter code.


--

 =C2=A0=C2=A0=C2=A0 Manfred


--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/343390da-2307-442e-8073-d1e779c85eeb%40colorfullife.com.

--------------7E09A4E938C7783C55499CA3
Content-Type: text/plain; charset=UTF-8;
 name="ipc-sem-dummy-change"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
 filename="ipc-sem-dummy-change"

ZGlmZiAtLWdpdCBhL2lwYy9zZW0uYyBiL2lwYy9zZW0uYwppbmRleCBiZjUzNGM3NDI5M2Uu
LjYwMjYxODdmNzlmOCAxMDA2NDQKLS0tIGEvaXBjL3NlbS5jCisrKyBiL2lwYy9zZW0uYwpA
QCAtODcsNiArODcsNyBAQAogI2luY2x1ZGUgPGxpbnV4L3NjaGVkL3dha2VfcS5oPgogI2lu
Y2x1ZGUgPGxpbnV4L25vc3BlYy5oPgogI2luY2x1ZGUgPGxpbnV4L3JoYXNodGFibGUuaD4K
KyNpbmNsdWRlIDxsaW51eC9qaWZmaWVzLmg+CiAKICNpbmNsdWRlIDxsaW51eC91YWNjZXNz
Lmg+CiAjaW5jbHVkZSAidXRpbC5oIgpAQCAtMzM2LDIwICszMzcsNDMgQEAgc3RhdGljIHZv
aWQgY29tcGxleG1vZGVfZW50ZXIoc3RydWN0IHNlbV9hcnJheSAqc21hKQogCWludCBpOwog
CXN0cnVjdCBzZW0gKnNlbTsKIAorCS8qIGNhbGxlciBvd25zIHNlbV9wZXJtLmxvY2sgLT4g
cGxhaW4gQyBhY2Nlc3MgKi8KIAlpZiAoc21hLT51c2VfZ2xvYmFsX2xvY2sgPiAwKSAgewog
CQkvKgogCQkgKiBXZSBhcmUgYWxyZWFkeSBpbiBnbG9iYWwgbG9jayBtb2RlLgogCQkgKiBO
b3RoaW5nIHRvIGRvLCBqdXN0IHJlc2V0IHRoZQogCQkgKiBjb3VudGVyIHVudGlsIHdlIHJl
dHVybiB0byBzaW1wbGUgbW9kZS4KIAkJICovCisJCS8qIGEgY2hhbmdlIGZyb20gYSBub24t
emVybyB2YWx1ZSB0byBhbm90aGVyCisJCSAqIG5vbi16ZXJvIHZhbHVlLiBQbGFpbiBDIGlz
IHN1ZmZpY2llbnQsIGFzIGFsbAorCQkgKiByZWFkZXJzIGVpdGhlciBvd24gc2VtX3Blcm0u
bG9jayBvciBhcmUgdXNpbmcKKwkJICogZGF0YV9yYWNlKCkgb3Igc21wX2xvYWRfYWNxdWly
ZSgpLgorCQkgKi8KIAkJc21hLT51c2VfZ2xvYmFsX2xvY2sgPSBVU0VfR0xPQkFMX0xPQ0tf
SFlTVEVSRVNJUzsKIAkJcmV0dXJuOwogCX0KKwkvKiBRdWVzdGlvbjogVGhpcyBwYWlycyB3
aXRoIHRoZSBzbXBfbG9hZF9hY3F1aXJlCisJICogaW4gc2VtX2xvY2soKSwgaW4gYSByYWN5
IHdheToKKwkgKiBUaGUgcmVhZGVyIGluIHNlbV9sb2NrKCkgbWF5IHNlZSB0aGUgbmV3IHZh
bHVlCisJICogaW1tZWRpYXRlbHksIC4uLgorCSAqLwogCXNtYS0+dXNlX2dsb2JhbF9sb2Nr
ID0gVVNFX0dMT0JBTF9MT0NLX0hZU1RFUkVTSVM7CiAKIAlmb3IgKGkgPSAwOyBpIDwgc21h
LT5zZW1fbnNlbXM7IGkrKykgewogCQlzZW0gPSAmc21hLT5zZW1zW2ldOwogCQlzcGluX2xv
Y2soJnNlbS0+bG9jayk7CisJCS8qIC4uLiwgb3IgbXVjaCBsYXRlci4KKwkJICogQnV0IHRo
aXMgaXMgdGhlIGxhdGVzdCBwb3NzaWJsZSB0aW1lOgorCQkgKiBzZW1fbG9jaygpIG93bnMg
b25lIG9mIHRoZSBzZW0tPmxvY2sgbG9ja3MKKwkJICogd2hlbiB1c2luZyBzbXBfbG9hZF9h
Y3F1aXJlKCkuIFRodXMgb25lIG9mIHRoZQorCQkgKiBzcGluX3VubG9jaygpcyBpbiB0aGlz
IGxvb3AgaXMgdGhlIF9yZWxlYXNlIGZvcgorCQkgKiB0aGUgcGxhaW4gQyB3cml0ZSBhYm92
ZS4KKwkJICogTXkgY3VycmVudCB1bmRlcnN0YW5kaW5nOiBQbGFpbiBDIGlzIGNvcnJlY3Qs
CisJCSAqIGFzIHRoZSByZWFkZXIgaXMgZWl0aGVyIHVzaW5nIGRhdGFfcmFjZSgpIG9yCisJ
CSAqIHNtcF9sb2FkX2FjcXVpcmUoKSwgb3IgaXQgaXMgYSB0cml2aWFsIGNhc2UKKwkJICog
b2YgdGhlIHJlYWRlciBvd25zIHNlbV9wZXJtLmxvY2sgLSBhbmQgd2Ugb3duCisJCSAqIHRo
YXQgbG9jayBhbGwgdGhlIHRpbWUuCisJCSAqLwogCQlzcGluX3VubG9jaygmc2VtLT5sb2Nr
KTsKIAl9CiB9CkBAIC0zNjYsMTEgKzM5MCwyMSBAQCBzdGF0aWMgdm9pZCBjb21wbGV4bW9k
ZV90cnlsZWF2ZShzdHJ1Y3Qgc2VtX2FycmF5ICpzbWEpCiAJCSAqLwogCQlyZXR1cm47CiAJ
fQorCS8qIHNlbV9wZXJtLmxvY2sgb3duZWQsIGFuZCBhbGwgd3JpdGVzIHRvIHNtYS0+dXNl
X2dsb2JhbF9sb2NrCisJICogaGFwcGVuIHVuZGVyIHRoYXQgbG9jayAtPiBwbGFpbiBDCisJ
ICovCiAJaWYgKHNtYS0+dXNlX2dsb2JhbF9sb2NrID09IDEpIHsKIAogCQkvKiBTZWUgU0VN
X0JBUlJJRVJfMSBmb3IgcHVycG9zZS9wYWlyaW5nICovCiAJCXNtcF9zdG9yZV9yZWxlYXNl
KCZzbWEtPnVzZV9nbG9iYWxfbG9jaywgMCk7CiAJfSBlbHNlIHsKKwkJLyogdGhlIHJlYWQg
c2lkZSBpcyBtYWtlZCAtPiBwbGFpbiBDLgorCQkgKiBRdWVzdGlvbjogT2xkIHZhbHVlIDQs
IG5ldyB2YWx1ZSAzLgorCQkgKiBJZiBpdCBtaWdodCBoYXBwZW4gdGhhdCB0aGUgYWN0dWFs
CisJCSAqIGNoYW5nZSBpcyA0IC0+IDAgLT4gMyAoaS5lLiBmaXJzdDoKKwkJICogY2xlYXIg
Yml0IDIsIHRoZW4gc2V0IGJpdHMgMCYxLCB0aGVuCisJCSAqIHRoaXMgd291bGQgYnJlYWsg
dGhlIGFsZ29yaXRobS4KKwkJICogSXMgdGhlcmVmb3JlIFdSSVRFX09OQ0UoKSByZXF1aXJl
ZD8gKi8KIAkJc21hLT51c2VfZ2xvYmFsX2xvY2stLTsKIAl9CiB9CkBAIC00MTIsNyArNDQ2
LDIwIEBAIHN0YXRpYyBpbmxpbmUgaW50IHNlbV9sb2NrKHN0cnVjdCBzZW1fYXJyYXkgKnNt
YSwgc3RydWN0IHNlbWJ1ZiAqc29wcywKIAkgKiBJbml0aWFsIGNoZWNrIGZvciB1c2VfZ2xv
YmFsX2xvY2suIEp1c3QgYW4gb3B0aW1pemF0aW9uLAogCSAqIG5vIGxvY2tpbmcsIG5vIG1l
bW9yeSBiYXJyaWVyLgogCSAqLwotCWlmICghc21hLT51c2VfZ2xvYmFsX2xvY2spIHsKKyNp
ZiAxCisJLyogdGhlIGNvZGUgd29ya3MgZmluZSByZWdhcmRsZXNzIG9mIHRoZSByZXR1cm5l
ZCB2YWx1ZQorCSAqIC0+IGRhdGFfcmFjZSgpLgorCSAqLworCWlmICghZGF0YV9yYWNlKHNt
YS0+dXNlX2dsb2JhbF9sb2NrKSkgeworI2Vsc2UKKwkvKiBwcm9vZiBvZiB0aGUgY2xhaW0g
dGhhdCB0aGUgY29kZSBhbHdheXMgd29ya3M6CisJICogTXkgYmVuY2htYXJrcyByYW4gZmlu
ZSB3aXRoIHRoaXMgaW1wbGVtZW50YXRpb24gOi0pCisJICovCisJaWYgKGppZmZpZXMlMikg
eworCQlwcl9pbmZvKCJqaWZmaWVzIG1vZCAyIGlzIDEuXG4iKTsKKwl9IGVsc2UgeworCQlw
cl9pbmZvKCJqaWZmaWVzIG1vZCAyIGlzIDAuXG4iKTsKKyNlbmRpZgogCQkvKgogCQkgKiBJ
dCBhcHBlYXJzIHRoYXQgbm8gY29tcGxleCBvcGVyYXRpb24gaXMgYXJvdW5kLgogCQkgKiBB
Y3F1aXJlIHRoZSBwZXItc2VtYXBob3JlIGxvY2suCkBAIC00MjAsNiArNDY3LDExIEBAIHN0
YXRpYyBpbmxpbmUgaW50IHNlbV9sb2NrKHN0cnVjdCBzZW1fYXJyYXkgKnNtYSwgc3RydWN0
IHNlbWJ1ZiAqc29wcywKIAkJc3Bpbl9sb2NrKCZzZW0tPmxvY2spOwogCiAJCS8qIHNlZSBT
RU1fQkFSUklFUl8xIGZvciBwdXJwb3NlL3BhaXJpbmcgKi8KKwkJLyogc21hLT51c2VfZ2xv
YmFsX2xvY2sgaXMgd3JpdHRlbiB0byB3aXRoIHBsYWluIEMKKwkJICogd2l0aGluIGEgc3Bp
bmxvY2sgcHJvdGVjdGVkIHJlZ2lvbiAoYnV0OiBhbm90aGVyCisJCSAqIGxvY2ssIG5vdCB0
aGUgc2VtLT5sb2NrIHRoYXQgd2Ugb3duKS4gTm8gbmVlZAorCQkgKiBmb3IgZGF0YV9yYWNl
KCksIGFzIHdlIHVzZSBzbXBfbG9hZF9hY3F1aXJlKCkuCisJCSAqLwogCQlpZiAoIXNtcF9s
b2FkX2FjcXVpcmUoJnNtYS0+dXNlX2dsb2JhbF9sb2NrKSkgewogCQkJLyogZmFzdCBwYXRo
IHN1Y2Nlc3NmdWwhICovCiAJCQlyZXR1cm4gc29wcy0+c2VtX251bTsKQEAgLTQzMCw2ICs0
ODIsMTAgQEAgc3RhdGljIGlubGluZSBpbnQgc2VtX2xvY2soc3RydWN0IHNlbV9hcnJheSAq
c21hLCBzdHJ1Y3Qgc2VtYnVmICpzb3BzLAogCS8qIHNsb3cgcGF0aDogYWNxdWlyZSB0aGUg
ZnVsbCBsb2NrICovCiAJaXBjX2xvY2tfb2JqZWN0KCZzbWEtPnNlbV9wZXJtKTsKIAorCS8q
IFRyaXZpYWwgY2FzZTogQWxsIHdyaXRlcyB0byBzbWEtPnVzZV9nbG9iYWxfbG9jayBoYXBw
ZW4gdW5kZXIKKwkgKiBzbWEtPnNlbV9wZXJtLmxvY2suIFdlIG93biB0aGF0IGxvY2ssIHRo
dXMgcGxhaW4gQyBhY2Nlc3MgaXMKKwkgKiBjb3JyZWN0LgorCSAqLwogCWlmIChzbWEtPnVz
ZV9nbG9iYWxfbG9jayA9PSAwKSB7CiAJCS8qCiAJCSAqIFRoZSB1c2VfZ2xvYmFsX2xvY2sg
bW9kZSBlbmRlZCB3aGlsZSB3ZSB3YWl0ZWQgZm9yCg==
--------------7E09A4E938C7783C55499CA3--
