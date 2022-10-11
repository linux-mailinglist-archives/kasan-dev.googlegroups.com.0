Return-Path: <kasan-dev+bncBCR5PSMFZYORBP75SSNAMGQE66ONUQQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ua1-x937.google.com (mail-ua1-x937.google.com [IPv6:2607:f8b0:4864:20::937])
	by mail.lfdr.de (Postfix) with ESMTPS id 5A6585FAFE6
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 12:00:32 +0200 (CEST)
Received: by mail-ua1-x937.google.com with SMTP id o43-20020ab0596e000000b0038421e4c7desf5202673uad.19
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Oct 2022 03:00:32 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1665482431; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xiwp0chj7+A9h1wGJj56tzQiv5Ntnz/isbkIfrZ47/E44YQEhv3jILJGeSth/sTtjO
         IpUHsdf8iT5tkQSHTwPnUkfnRnLgqB0NWlo0sVyohngP+0k6d9jAcZzmV6s7O0AEbv+l
         ztxpeIO/e28K9rFw5dx82NyM6tlOgAALCyra0aGHliri3/CqpNTXAVHNpElJc5lRHJGJ
         zjSkksDef0m0EvU723rQXiqemB67sx90B1+6w4S3JWUQwduItC6sVyhcgQ/zGznaM2AO
         /cbRqFPTX8ITElnYIovbg4ILb63Cfrik6Bj0eFnIQEy6i7HTppCT99/3yBpIBpHMsl/7
         9vPA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:message-id:date:references:in-reply-to:subject:cc:to
         :from:sender:dkim-signature;
        bh=IezIvlfws1O92EGokK6ZWydYFUUHNGcRQ/XDDl5iwR8=;
        b=uKg1ktxMKeJCUdAWjEi5TtAJjy38CM+4ItKdDusCJE6++/i1tmHOJNvt096di0znu2
         LE/QIEm621Xy5hbt8vlXE5hZXj7YxVPx0J5hwqtoEzDIPYJkF5eb7DcYnFXLANH5pLKp
         xEm8pj7W+AxR8K10ex8CDzV0iZBK33ruVkhdUwKzdnXtgBQIKmDI0wA6OfAAFzirwsnk
         3P4T/BIcuhv+r7Kla/XYkgi8Fzq3YXSzwjHvFp2zy2b+MJwPR+3Q3H58pIcuFlFK47Fp
         nVpLKLtWgk2tnhXUxZZIGXxZs9RzWzzQtepRta+wIjjmpt9nIzVKpelvaUvE8fY0KK5O
         y80g==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=Z1xv0caE;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:message-id
         :date:references:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IezIvlfws1O92EGokK6ZWydYFUUHNGcRQ/XDDl5iwR8=;
        b=KYnFdkJUUE2Pz8ArBzo/Cb1siyTA/2mSrORmrNlDmt7VMR6LsX6W8DbYZNnaWkq67E
         loQXmGcMpji35gzZCp8bqpWC+0ni6DFnSJ/ab0D13UGb8Q2GB8i621fjXmqWNB0kJUIH
         Vj5RnsT784kO7KYkPh6qUkXfjEh4rfq/Zwjl7CAeXNPWEh97kFxabmJ9362dyzuQr41y
         /IiClz4VCBcgx66VQDGoV6LDwVd1fcPFH4XF9VaBf1xemhgwmUz0b/nyWcVgyBw6Hpw5
         HkeY52Gb81ZraPdllpN9tFIO6cg7USSacB6HbD/9fZPJg7CvtCtn48E6VfRmrYjM6DH1
         b5Ig==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=IezIvlfws1O92EGokK6ZWydYFUUHNGcRQ/XDDl5iwR8=;
        b=Xjt7nUvu9vzeHaMNYXGyA3Fhsm07tom9KnxJI9tlCdCz8yMU1LjtYMrFVpMwXdc7qE
         Ex7zGS1BtB0OKKPkyY0b7TTiRw19YxNkJxnKKgvDkuI+YEK1ikAMnysJZAKW9iTFu4za
         SbPVPTVddMPBiVnNx45COoSYN0rGzxzyKFqzESXRV1ZM69GSmf7nonpXdtiKJccUarJ6
         u1DsCf5Ili8kjXpMRJ6Aikq+8a7NttV4WvSKwGtzAvTxvNtxeNxGt1ZBwR9rJQKeDtAD
         Iq1KyL4moDgquv6mxBy1HV/81XcG85w3RqsyzOmFmAV/S5l6RfxCS/ccckU0Oc3TvTc+
         hWaw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: ACrzQf0ckkApeCHkrNBsfhCavwzBfPsPLWFjVyBl9zv7Z3s1oMOQoNVD
	ch3lgd+j4L1C0hF65FS05p4=
X-Google-Smtp-Source: AMsMyM5YQIH2yOmtx5clH3BJ72vuqhyfJ3JvhJKaG4pd1B3wGFwSyrpq/SayTxGuqJAHdK5+qkueAg==
X-Received: by 2002:a1f:29cc:0:b0:3ab:44c4:bf8b with SMTP id p195-20020a1f29cc000000b003ab44c4bf8bmr10279772vkp.25.1665482431326;
        Tue, 11 Oct 2022 03:00:31 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9f:3382:0:b0:3b3:6d5a:e75d with SMTP id p2-20020a9f3382000000b003b36d5ae75dls970819uab.10.-pod-prod-gmail;
 Tue, 11 Oct 2022 03:00:30 -0700 (PDT)
X-Received: by 2002:ab0:6494:0:b0:3da:7cac:c48d with SMTP id p20-20020ab06494000000b003da7cacc48dmr10801550uam.96.1665482430781;
        Tue, 11 Oct 2022 03:00:30 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1665482430; cv=none;
        d=google.com; s=arc-20160816;
        b=nyDUJD7efDApihv96jou9LkOdWG27xt9pZP987PpR6Gd4FDtpH2WgNKztiGNxqR0Fs
         NWs3sAOxqgsVy+sFOcplPR0wGs8lK6Fv8qjEPF/dB1vVjhIKFQXuyMU7LyCVO90cTJqy
         BOLt5JmSUT/hI+oqKL85iDW48uORQAiVqSbgUhPLRd3PSOfndiQZaYadOeJN96earaO1
         KIQwHzM179J02nhc49OApVz1XC7QRcQpMsJX8/paMT/XzuUlAUg4vKUQOeKG2dHLs5Aq
         Cwo3QZLKYmHe7n9x2/KkpFcbpzkIb4YGlAYrEtK+vn4+lR2gZ43qpWWDOpexoOB13R3n
         n4qw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:references
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=jTNpC/83zi25X5OXSPkigIE3/qAhV8pkp82d8ZJjJzA=;
        b=OF1pjqKQlha9u6QvhFbgNsJuHN5M3O0V1DjKac/iiWXQEyTLEIIUS5sCB3VcPN5ql/
         ru7CZKDziphUPqTNlMmoG1neVjd9QYxlLX/GK18Y73G2QBH0JcEAYbi7n9e2OqgtlCJm
         JQH5hgj2sPtRYGa+gubudI/lG4WDdrxuCPYuuaJQaBIDLdVoJsdIQL1NDGYd0Y7FO26/
         Wik2IGFF1UgB0ny+vzq1Y+ITZ5vk9vv8nS5hgV4AWCSjGCwW2BMCWF4222LfYMXWPeNk
         SS+xS6zLKEvq3Lsi1slo46MIf1jyCb9yGAnbOPROpX74qA5cXgRigmLN7Lj7/Um0aU5V
         pITg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@ellerman.id.au header.s=201909 header.b=Z1xv0caE;
       spf=pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
Received: from gandalf.ozlabs.org (mail.ozlabs.org. [2404:9400:2221:ea00::3])
        by gmr-mx.google.com with ESMTPS id r11-20020ab06f0b000000b003d919da0471si2189901uah.1.2022.10.11.03.00.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Tue, 11 Oct 2022 03:00:30 -0700 (PDT)
Received-SPF: pass (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3 as permitted sender) client-ip=2404:9400:2221:ea00::3;
Received: from authenticated.ozlabs.org (localhost [127.0.0.1])
	(using TLSv1.3 with cipher TLS_AES_256_GCM_SHA384 (256/256 bits)
	 key-exchange ECDHE (P-256) server-signature RSA-PSS (4096 bits) server-digest SHA256)
	(No client certificate requested)
	by mail.ozlabs.org (Postfix) with ESMTPSA id 4Mmrr955PXz4xGl;
	Tue, 11 Oct 2022 21:00:25 +1100 (AEDT)
From: Michael Ellerman <mpe@ellerman.id.au>
To: Nathan Lynch <nathanl@linux.ibm.com>
Cc: Christophe Leroy <christophe.leroy@csgroup.eu>,
 "linuxppc-dev@lists.ozlabs.org" <linuxppc-dev@lists.ozlabs.org>, kasan-dev
 <kasan-dev@googlegroups.com>
Subject: Re: [PATCH] powerpc/kasan/book3s_64: warn when running with hash MMU
In-Reply-To: <8735bvbwgy.fsf@linux.ibm.com>
References: <20221004223724.38707-1-nathanl@linux.ibm.com>
 <874jwhpp6g.fsf@mpe.ellerman.id.au>
 <9b6eb796-6b40-f61d-b9c6-c2e9ab0ced38@csgroup.eu>
 <87h70for01.fsf@mpe.ellerman.id.au> <8735bvbwgy.fsf@linux.ibm.com>
Date: Tue, 11 Oct 2022 21:00:25 +1100
Message-ID: <87v8oqn0hy.fsf@mpe.ellerman.id.au>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: mpe@ellerman.id.au
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@ellerman.id.au header.s=201909 header.b=Z1xv0caE;       spf=pass
 (google.com: domain of mpe@ellerman.id.au designates 2404:9400:2221:ea00::3
 as permitted sender) smtp.mailfrom=mpe@ellerman.id.au
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

Nathan Lynch <nathanl@linux.ibm.com> writes:
> Michael Ellerman <mpe@ellerman.id.au> writes:
>> Christophe Leroy <christophe.leroy@csgroup.eu> writes:
>>> + KASAN list
>>>
>>> Le 06/10/2022 =C3=A0 06:10, Michael Ellerman a =C3=A9crit=C2=A0:
>>>> Nathan Lynch <nathanl@linux.ibm.com> writes:
>>>>> kasan is known to crash at boot on book3s_64 with non-radix MMU. As
>>>>> noted in commit 41b7a347bf14 ("powerpc: Book3S 64-bit outline-only
>>>>> KASAN support"):
>>>>>
>>>>>    A kernel with CONFIG_KASAN=3Dy will crash during boot on a machine
>>>>>    using HPT translation because not all the entry points to the
>>>>>    generic KASAN code are protected with a call to kasan_arch_is_read=
y().
>>>>=20
>>>> I guess I thought there was some plan to fix that.
>>>
>>> I was thinking the same.
>>>
>>> Do we have a list of the said entry points to the generic code that are=
=20
>>> lacking a call to kasan_arch_is_ready() ?
>>>
>>> Typically, the BUG dump below shows that kasan_byte_accessible() is=20
>>> lacking the check. It should be straight forward to add=20
>>> kasan_arch_is_ready() check to kasan_byte_accessible(), shouldn't it ?
>>
>> Yes :)
>>
>> And one other spot, but the patch below boots OK for me. I'll leave it
>> running for a while just in case there's a path I've missed.
>
> It works for me too, thanks (p8 pseries qemu).

It works but I still see the kasan shadow getting mapped, which we would
ideally avoid.

From PTDUMP:

---[ kasan shadow mem start ]---
0xc00f000000000000-0xc00f00000006ffff  0x00000000045e0000       448K       =
  r  w       pte  valid  present        dirty  accessed
0xc00f3ffffffe0000-0xc00f3fffffffffff  0x0000000004d80000       128K       =
  r  w       pte  valid  present        dirty  accessed

I haven't worked out how those are getting mapped.

> This avoids the boot-time oops, but kasan remains unimplemented for hash
> mmu. Raising the question: with the trivial crashes addressed, is the
> current message ('KASAN not enabled as it requires radix!') sufficient
> to notify developers (such as me, a week ago) who mean to use kasan on a
> book3s platform, unaware that it's radix-only? Would a WARN or something
> more prominent still be justified?
>
> I guess people will figure it out as soon as they think to search the
> kernel log for 'KASAN'...

Yeah, I think a warning is a bit too strong. I think that's more likely
to lead to bug reports than anything :)

cheers

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87v8oqn0hy.fsf%40mpe.ellerman.id.au.
