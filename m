Return-Path: <kasan-dev+bncBCR6PUHQH4INV5GCWIDBUBHAQCOTO@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd3b.google.com (mail-io1-xd3b.google.com [IPv6:2607:f8b0:4864:20::d3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D4F38CE86D
	for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 18:03:40 +0200 (CEST)
Received: by mail-io1-xd3b.google.com with SMTP id ca18e2360f4ac-7e69c0762b8sf310383039f.1
        for <lists+kasan-dev@lfdr.de>; Fri, 24 May 2024 09:03:40 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1716566619; cv=pass;
        d=google.com; s=arc-20160816;
        b=nnAKUnvYnUpPy9nW3nogVs3vEVB5atToEZTDvfa/vQ5w9AoIWk4SauA8Y9R25aIhW6
         Cn4mRCGVqT6CAGXMKEpGC1oTnFHuA+/RFnzabDt0VjamNkE+DQPcHN+lYtm4MjbWgjAD
         63v+bmLzlGR3PCgX5bfRlDhNRlcoaGsBFNeO2uyBK3SMm/dIC+gqVkQcxcjc1a0Ni0S3
         VytmdqAXwWU1DJuz96P5z4PgHfUxBXWVUw5xaVexv63KlSz0BSayEI5tu1HrbwY8QaUp
         UVtkOnx6YRR9Oww+eIYMOJRhAG0dDpSdrsZLhtIyppStm0/2Dtd653oCRMlE63w7Ann1
         LTFA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :in-reply-to:content-language:references:cc:to:from:subject
         :user-agent:mime-version:date:message-id:sender:dkim-signature;
        bh=Vq1lfoLrmgt/XzmF/DKttaEuRIHkAXNpnrK9mvIQut0=;
        fh=/zlqHbYMr2t6lorTlSu0taqNI+fIrTKVMTFA8R1RcXc=;
        b=dh7ApsOJy2boXl9B5RicI8uuwufTYRTj7CWEyVtrCWSw1FRdMlbWfYY/bh0/1gHUol
         9H9oeud+My2uZcNzFCYirPYqJgxA7lMa0E+zgAhv+DGQN4JsWKr8zY//vQ+ckq/tdlwk
         /Kdl7tIZUCocp53rU/cNtDbksu1JzUN0M0RO6x3VPTTBEpgUPKvAHXTozanLcQZT0WwA
         WUQTo7fjy5RyPRgnpdUuIP/qLNFXEN/HUvOk8UjFBbx8IgL0u0Fu/NjzicgIWfGrphj0
         onl4AHiFySoUWtUas8vRMTrFwKcB6lbwQxEaAvjWyc3QLQWvJy4zL0RWLt/pXOJ28Qg9
         PidQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=BJ7hrmY5;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1716566619; x=1717171419; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:in-reply-to
         :content-language:references:cc:to:from:subject:user-agent
         :mime-version:date:message-id:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Vq1lfoLrmgt/XzmF/DKttaEuRIHkAXNpnrK9mvIQut0=;
        b=sIp19I8CsCA3S4oUdbSUpVC4MeEgjuI5Kkv451oE25f3CQkJpQucdrJHf1dcPK2U0m
         JRk8UFGrxhIVC54nNe8AAxzT9e4+pAku42OCIMyt9DAN/oR+CUmDhHCJUA4c4rXaPmVW
         P2ZcFGhx7xaP9Iad+WGuXjw4xoddEdwqQUS/ocQTGZdnZxCqVXGN/BKvGj/0+L7fF5fL
         b4cOtnyRJfFSMt7TUG4zdJ/3cCIwnNuSoPq/CjcpKfWLOggLu6goSlXshsoQn3oQBEK2
         8Z0Wgq8erl2tZeakuVzG+hORZb8Ec5swC91SIb2Z/K3690enELLnzzVGG5nqFLaWd2xZ
         anfg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1716566619; x=1717171419;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Vq1lfoLrmgt/XzmF/DKttaEuRIHkAXNpnrK9mvIQut0=;
        b=l1CzesloZa9lADNNz1gH5B6IIVCCOk9dq6sqv+AuCNLWgPTKxf9B/058y4A8UV5YvK
         8nIs9ZSZWqWTkbSaKRreUGOexRT/ggcnnVRwrzOy5ajF0r7Wz/g4voCjkHFtA8lZy/dh
         fy32mjTSg+oo44We5z8HkV2oEc1ojBIjhY60irf+TVGbQ+LdGPwdtAscyRX4qC/jM59l
         hLi0aSBBlYa96TCqE8aCKnTevtHn17EeyVheQHoidFhWeNAlIaRh/JagtXfxIZp9rape
         n/B4txq4bWteZNReg9XnwVK3KTidB0jqoqLLPrWel1zANUTeheFUjMNoJSFRRKbGcGGg
         Bb+g==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCXcoLKbl4+6Tc+Dd45WE75iFRVqR/fJsbyPRiPNWRY5uQjvRU5lh8H0baLfwEs674xdKU0i+DcQG1SJq83Qogp2vfzy/+Dk1A==
X-Gm-Message-State: AOJu0Yy+RIGUDCixN9h+PzWRP9F9v/C4Rej6T1lwdKMT1wi4awkwlMpW
	mOVj6HiT7HFCTNIPOBKuiWtn3FwhOvZSOf5npYSDB5cof65PSrth
X-Google-Smtp-Source: AGHT+IEZ7UzMM0wb0vWTPiKKhVBjvz4ilOQHRhHsVGqtKeSFwNj3doNGLRSjJrcgLbwdPuYaNkVuUQ==
X-Received: by 2002:a05:6e02:1aa3:b0:36a:3fb1:6499 with SMTP id e9e14a558f8ab-3737b237970mr30115765ab.2.1716566618641;
        Fri, 24 May 2024 09:03:38 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:164d:b0:372:9a47:575b with SMTP id
 e9e14a558f8ab-3737a5eb83dls8331805ab.0.-pod-prod-09-us; Fri, 24 May 2024
 09:03:36 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUmQlqvutvsRbDXT4g435A60aIyLXw+7H8STwFjYUhFnMgQuVhCHixIfMwuOXXHyQBJ0qOAi9BJOANQxpQPPUTZgbS5SabD1w6/Lg==
X-Received: by 2002:a05:6602:3f94:b0:7e1:acdd:962e with SMTP id ca18e2360f4ac-7e8c53ca236mr421854639f.12.1716566615772;
        Fri, 24 May 2024 09:03:35 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1716566615; cv=none;
        d=google.com; s=arc-20160816;
        b=VT11qXrsc0ocueNd581QHSLot85AVHuZS9FgXRD3mCUJQCVwl1d9yQk1szfsS7RSpf
         2CgqRLtZNGY7s3gmVXX8nbUfvz+cDzXVyKiNkipPKKiBr34zRWqhcK5mymjZ88uPqVxD
         UMdVYdGFUWxsULMY3T69zm7rkkIAqXyoMzy4DJhDPRZ/RO7GlvyDYOsxfvqg20W4EBuV
         MzfaumCaw8p8opQGx/V4Y99UqqPABnmxSO2wHHOzwWQzJeaV5iDELyYsMKhPa8DFG6X3
         6Rg2m5p6dPm8sEAznYBCUT0FWVCiuc3avorhajOwymJNi0r+MBNdldtsNhts3D+LaDkM
         TmLA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:in-reply-to:content-language:references
         :cc:to:from:subject:user-agent:mime-version:date:message-id
         :dkim-signature;
        bh=fPJj/5KVQ/VNCoPmhbwEkAAfXadkRlm7Bb0P1QufmFk=;
        fh=1rwarnBK5lKkIS5wPP901k5vFabioac5KyOvP020e/k=;
        b=NYzLeaht6FffIhAP4mTdb6ctbII3uVDhLVTx96SeauwLNxKOOIvDsz36cnOdcKYbzA
         /yR9sp0ow1eZJE7zbKhG6BPNFXBu5ZfEp8yNrGNBQlspynYNmBdK9VGohij9TU3R3wyr
         rLLRxUVI2lNrbxCGwn6IiVyctErvNcnn82gy8Wbt9KRHCC7xduQcpsTctr5XtgDq0LCB
         OizDe/2D04Y33IVToUMM2rwQGjp48kQ8ns3SayiWwBTvfoli9s54G9BMRK3IHTKSrdEy
         DC8nxDMxcDiVXfjfaFMx6/zZitHHBar95LwvH/V8fZNcjjfK04D1L4b/XXcPO03dR7jK
         7nfA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@efficios.com header.s=smtpout1 header.b=BJ7hrmY5;
       spf=pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
Received: from smtpout.efficios.com (smtpout.efficios.com. [2607:5300:203:b2ee::31e5])
        by gmr-mx.google.com with ESMTPS id ca18e2360f4ac-7e90677bf94si6646339f.2.2024.05.24.09.03.35
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 24 May 2024 09:03:35 -0700 (PDT)
Received-SPF: pass (google.com: domain of mathieu.desnoyers@efficios.com designates 2607:5300:203:b2ee::31e5 as permitted sender) client-ip=2607:5300:203:b2ee::31e5;
Received: from [172.16.0.134] (192-222-143-198.qc.cable.ebox.net [192.222.143.198])
	by smtpout.efficios.com (Postfix) with ESMTPSA id 4Vm8wQ4q9Dz11J8;
	Fri, 24 May 2024 12:03:34 -0400 (EDT)
Message-ID: <7236a148-c513-4053-9778-0bce6657e358@efficios.com>
Date: Fri, 24 May 2024 12:04:11 -0400
MIME-Version: 1.0
User-Agent: Mozilla Thunderbird
Subject: Re: Use of zero-length arrays in bcachefs structures inner fields
From: Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
To: Kent Overstreet <kent.overstreet@linux.dev>
Cc: Brian Foster <bfoster@redhat.com>, Kees Cook <keescook@chromium.org>,
 linux-kernel <linux-kernel@vger.kernel.org>, linux-bcachefs@vger.kernel.org,
 Alexander Potapenko <glider@google.com>, Marco Elver <elver@google.com>,
 Dmitry Vyukov <dvyukov@google.com>, kasan-dev@googlegroups.com,
 Nathan Chancellor <nathan@kernel.org>,
 Nick Desaulniers <ndesaulniers@google.com>, Bill Wendling
 <morbo@google.com>, Justin Stitt <justinstitt@google.com>,
 llvm@lists.linux.dev
References: <986294ee-8bb1-4bf4-9f23-2bc25dbad561@efficios.com>
 <vu7w6if47tv3kwnbbbsdchu3wpsbkqlvlkvewtvjx5hkq57fya@rgl6bp33eizt>
 <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com>
Content-Language: en-US
In-Reply-To: <944d79b5-177d-43ea-a130-25bd62fc787f@efficios.com>
Content-Type: text/plain; charset="UTF-8"; format=flowed
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mathieu.desnoyers@efficios.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@efficios.com header.s=smtpout1 header.b=BJ7hrmY5;       spf=pass
 (google.com: domain of mathieu.desnoyers@efficios.com designates
 2607:5300:203:b2ee::31e5 as permitted sender) smtp.mailfrom=mathieu.desnoyers@efficios.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=efficios.com
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

On 2024-05-24 11:35, Mathieu Desnoyers wrote:
> [ Adding clang/llvm and KMSAN maintainers/reviewers in CC. ]
>=20
> On 2024-05-24 11:28, Kent Overstreet wrote:
>> On Thu, May 23, 2024 at 01:53:42PM -0400, Mathieu Desnoyers wrote:
>>> Hi Kent,
>>>
>>> Looking around in the bcachefs code for possible causes of this KMSAN
>>> bug report:
>>>
>>> https://lore.kernel.org/lkml/000000000000fd5e7006191f78dc@google.com/
>>>
>>> I notice the following pattern in the bcachefs structures: zero-length
>>> arrays members are inserted in structures (not always at the end),
>>> seemingly to achieve a result similar to what could be done with a
>>> union:
>>>
>>> fs/bcachefs/bcachefs_format.h:
>>>
>>> struct bkey_packed {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __u64=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 _data[0];
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 /* Size of combined ke=
y and value, in u64s */
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __u8=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 u64s;
>>> [...]
>>> };
>>>
>>> likewise:
>>>
>>> struct bkey_i {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 __u64=C2=A0=C2=A0=C2=
=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=
=C2=A0=C2=A0=C2=A0 _data[0];
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct bkey=C2=A0=C2=
=A0=C2=A0=C2=A0 k;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct bch_val=C2=A0 v=
;
>>> };
>>>
>>> (and there are many more examples of this pattern in bcachefs)
>>>
>>> AFAIK, the C11 standard states that array declarator constant expressio=
n
>>>
>>> Effectively, we can verify that this code triggers an undefined behavio=
r
>>> with:
>>>
>>> #include <stdio.h>
>>>
>>> struct z {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int x[0];
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int y;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 int z;
>>> } __attribute__((packed));
>>>
>>> int main(void)
>>> {
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 struct z a;
>>>
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 a.y =3D 1;
>>> =C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0=C2=A0 printf("%d\n", a.x[0])=
;
>>> }
>>> delimited by [ ] shall have a value greater than zero.
>>
>> Yet another example of the C people going absolutely nutty with
>> everything being undefined. Look, this isn't ok, we need to get work
>> done, and I've already wasted entirely too much time on ZLA vs. flex
>> array member nonsense.
>>
>> There's a bunch of legit uses for zero length arrays, and your example,
>> where we're not even _assigning_ to x, is just batshit. Someone needs to
>> get his head examined.

Notice how a.y is first set to 1, then a.x[0] is loaded, expecting to
alias with a.y.

This is the same aliasing pattern found in bcachefs, for instance here:

bcachefs_format.h:

struct jset {
[...]
         __u8                    encrypted_start[0];

         __le16                  _read_clock; /* no longer used */
         __le16                  _write_clock;

         /* Sequence number of oldest dirty journal entry */
         __le64                  last_seq;


         struct jset_entry       start[0];
         __u64                   _data[];
} __packed __aligned(8);

where struct jset last_seq field is set by jset_validate():

		jset->last_seq =3D jset->seq;

and where journal_read_bucket() uses the encrypted_start member as input:

                 ret =3D bch2_encrypt(c, JSET_CSUM_TYPE(j), journal_nonce(j=
),
                              j->encrypted_start,
                              vstruct_end(j) - (void *) j->encrypted_start)=
;

Regards,

Mathieu


>>
>>> So I wonder if the issue reported by KMSAN could be caused by this
>>> pattern ?
>>
>> Possibly; the KMSAN errors I've been looking at do look suspicious. But
>> it sounds like we need a real fix that involves defining proper
>> semantics, not compiler folks giving up and saying 'aiee!'.
>>
>> IOW, clang/KMSAN are broken if they simply choke on a zero length array
>> being present.
>=20

--=20
Mathieu Desnoyers
EfficiOS Inc.
https://www.efficios.com

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/7236a148-c513-4053-9778-0bce6657e358%40efficios.com.
