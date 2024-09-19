Return-Path: <kasan-dev+bncBDS6NZUJ6ILRBUEGV63QMGQEUKRHQ3Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qv1-xf3c.google.com (mail-qv1-xf3c.google.com [IPv6:2607:f8b0:4864:20::f3c])
	by mail.lfdr.de (Postfix) with ESMTPS id EB39097C43A
	for <lists+kasan-dev@lfdr.de>; Thu, 19 Sep 2024 08:23:19 +0200 (CEST)
Received: by mail-qv1-xf3c.google.com with SMTP id 6a1803df08f44-6c36e60b5f9sf11320546d6.2
        for <lists+kasan-dev@lfdr.de>; Wed, 18 Sep 2024 23:23:19 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1726726992; cv=pass;
        d=google.com; s=arc-20240605;
        b=brGEIge7l1k2TaIMmfKQMzVPOB2jFrm1vCce4lVpU8kvggQ2vmOUPVeSZJhR2gCbEk
         8p2Bwu6iv28kQ1Jgb9fGOVhiXCqPJiLfFowK45Dw+tT6X6rfGAjihNKxWSdRvjBRc4IK
         b3WMuU7sqyrkSW+kY9FgZyLhjui+YOp0wLkjVvW5Pkq/nJ6psAWV2Vlul+WdRAWqDKjV
         GrIgADV8uHoAqLod8CSy2tESbRxe+eIaaZ8egRTrypFWQKrD8JKsr6xQqcFDuaZwQmfo
         ZMrCtwOa5B3hw1W9lLZdi9qKh3tGBG3wWz9DA4JZpzuq4LWlzN32/0+kKtxxZfUmbKiI
         k+Dg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding
         :mime-version:references:message-id:date:in-reply-to:subject:cc:to
         :from:sender:dkim-signature:dkim-signature;
        bh=2s2pqw2KKsFbln2ZEZXWC0YjekbBid0/Pp7t2pIizok=;
        fh=wrS/RIrXXChekX3EAcDB2QBRqxqbJOKjKiCauiPHN+Y=;
        b=LRQhBVE9/6uOzozpdAhHKysc83aVNr/yKP+wHey823FjkA84SgBoRIaMaq7AngWg2y
         lRG9ev3Si02l6suswL8MIc+WRK1h5QQTZBKxBvcu9l7eKp9egSxIHRsXW3Qud5/Hp52t
         Fv4nyeHEQ/h5UyDFyYaIK4WIcS5Y4UnqZ43lMywGmzdYhyhZA+5KjzVoKCSLmPUcMM+i
         Ee1k8NeMPjqXu6/zLykU+HnPPJ0NYNyrFBpCqWT2ig8cWw7ThVifcMig22uimZGiQkYi
         82l3S2L080RYhHm+VBPWnVN0v2uFI+FFg1OGlj2m3DqOFO/OTOqt5HOkvmZVsQdPF1ML
         UM0g==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OfGuLZ0t;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1726726992; x=1727331792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :message-id:date:in-reply-to:subject:cc:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=2s2pqw2KKsFbln2ZEZXWC0YjekbBid0/Pp7t2pIizok=;
        b=YJ2qJcGp/My2PvqcpncwU7BaN57PpMmq9YdqBvkBV0y6mZdV5f1ZvC2vNPCj6MKboJ
         +Agq80PulkpTAz+XUQMH0j0nIq/kSVgkZ+hbzp8euSpem17uilRh/9IBEZ3nqh5pWmR4
         qc5Cd6G8M1sIRGVGHIVJswjrF9u41RaV88QvNp0G3tl8zati4rQo6am0lzzBiEVonO+i
         To0qTktc3qaNggeRYb3cA9k29kFhguMhTNsH+Q+zle/CQ9tY0HGk+LGAdA7GFKRmtmy0
         DMFBmjEsa+lQVddncOMBTftnn7CbjDknzKPLco2zolSxfkn+dw8h731FyztsoSidUTFV
         rSZw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1726726992; x=1727331792; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:mime-version:references
         :message-id:date:in-reply-to:subject:cc:to:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=2s2pqw2KKsFbln2ZEZXWC0YjekbBid0/Pp7t2pIizok=;
        b=EEW65vh3gvvfDMTxqwmOGn62T09L/iEHTI8jWtbrw2ltUh9zbyxOfSCO+hoPBWwG8c
         pOp5fW9Yn4vaCUMks7gCLwE+EKnqVKUhGNWF1rJWXwlygLsLv5pckkwu+hEv9S4et8Zg
         9FSoLl9GDrhbnoJIjnH2tihQaSTvxUmPssEUlwzM6vUN1M7bT42C9/73FuNY/YawRe68
         mu9C8NpZAmpoe9/aPcOhHwq7IeFiS801sRpvGA1444k0m7fdrtpO1wxNDHHFdmCEaZEJ
         91nN3MIIZRQKdXATF7X+F5cyxYX4M5Inh6WDhGTzDibxvoayld78ia/kLz0v5lUcGqWQ
         Dj4Q==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1726726992; x=1727331792;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=2s2pqw2KKsFbln2ZEZXWC0YjekbBid0/Pp7t2pIizok=;
        b=KEhPcmgrxWdo/6Axptohs2RdXg4fqGA6RM9cIj3z1QwJGWpudsC5YjjcMKrL8UgdKu
         9IYcDt4QeyL6lVXYJsUWq4u8Y1ekA2GCa26Lx06NONiVDEOF5IeTS+5Cbi1ZglPK24zF
         r/Jeq5EsRyD3gyUrk/w3NZIO84/bYI/JBlQwYi2KMDMHWQ+boKM8obD92dfwubYPWOfO
         5CiKCjXV7JtILGd9gbYd0eh8lbjEddU6fceDezYuX+05YbdRivJ3PBSyOgK9sz/YcsUS
         LOd2xsEcAa+T36I57U2rFlqmiP9u9qEnwus1nDog9ntA/CHFipzdWMkYnOvGX0pLKwtB
         PQZw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVc5FeQyOsZUoMAhDw40liBATfYZa9jQCeWsDceLpAUQITyLMeDkVosGZS+0qKfE88shr8orA==@lfdr.de
X-Gm-Message-State: AOJu0YyBVkRTr9V472WvPapPnfCqfa+MG+62fsOfY+UtOG26n6UQK+ja
	UIfEvRiqv1cgnZ0AgJwrWYXt+UvVBCZLTk1VlBTX8R1Qie2V8qX0
X-Google-Smtp-Source: AGHT+IE+22L23UjYtmpwLCkDRfMXiIoN9QwZxZnhYWqIYY8DhSl1ReWg25p2PBrOZqboyeFYBNuoJQ==
X-Received: by 2002:a05:6214:285:b0:6c5:26ac:d857 with SMTP id 6a1803df08f44-6c57e136591mr230953306d6.50.1726726992225;
        Wed, 18 Sep 2024 23:23:12 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5f08:0:b0:6bd:735f:a70e with SMTP id 6a1803df08f44-6c6823adeffls10122776d6.0.-pod-prod-06-us;
 Wed, 18 Sep 2024 23:23:11 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVGV81EWj+1iJe1Wky8UQNrUPBnzEpPLYLe+7jzOdxSpPTWbCKLBY6D+gv3ltp55+tRnVgydGi+XKo=@googlegroups.com
X-Received: by 2002:a05:6214:5c02:b0:6bf:aa45:d1f7 with SMTP id 6a1803df08f44-6c57dfbdbf3mr297570286d6.27.1726726991488;
        Wed, 18 Sep 2024 23:23:11 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1726726991; cv=none;
        d=google.com; s=arc-20240605;
        b=KxNCBPTUAnX+VUt+gNczaSEReZT/2WszBYak0xbYXH/FsdnIslu83QTPwJQ63Czekj
         XAV0K1TxCg6JMoQi9bc7xmnaG/8BbUzxQjN+Yw6KuoF8I/i10t0AQ0qkkNOUhNtecf9C
         Mm8fBhLmb5TBmivXKt09YGIJ/26JS6NWy7DKThJIYi/4d0JyVZPTU0DZXboQuSYCT0R/
         bvEw+LdHoqVFibDlVslajConvhdDKnz4ZPBrSkmtNWyTAe97ZrVLxyF8o74CXxntd/0c
         3X1wW1Oe6V1RT5Csc0qAHcbFTbyL6hVKqFWSPCPhxSjjPcj7SqFww8tBNDW2a1JgcpkW
         AXUg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:references:message-id:date
         :in-reply-to:subject:cc:to:from:dkim-signature;
        bh=lMB28cCoh+EtgWHGA1hGa1Xqf23n12o3JH476WnchVA=;
        fh=aSVd83+EC4vjNl7cB/bYUtyAAkNF2kj6LjMOu54GKVI=;
        b=SaLB/m9lfasR2H+vzqrCBCfxTIx0PL0xhmArhguRbeIVnxXhVGWV1ea94l7ouMQLGx
         Kf+kt9O4jPc/i/XSyIyfwpCacLynYTrFTUMAV8g0juue88Q3ts9dk8MHlD1suavdpGE7
         uHv9VVehZWTMq7RHC9wQloMdkdj2sQmtzO4G6igWw+Ckp8gJYSeRf7DfbElExno1qUqg
         CyImEmzyo9jw2/IyEbi5XTdV4oAcRnlMhXgJam1Swqdb8zPS2g0XNGiFyOvlpzM0QrQo
         gFLe7n2rU1s1w15IMh6d92GMNM7mUwtVdKnzoOpAcqGFiDBw2GA7gn8Q/+v8QTWfBkJn
         aVow==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=OfGuLZ0t;
       spf=pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pl1-x636.google.com (mail-pl1-x636.google.com. [2607:f8b0:4864:20::636])
        by gmr-mx.google.com with ESMTPS id 6a1803df08f44-6c75e585925si585666d6.6.2024.09.18.23.23.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 18 Sep 2024 23:23:11 -0700 (PDT)
Received-SPF: pass (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636 as permitted sender) client-ip=2607:f8b0:4864:20::636;
Received: by mail-pl1-x636.google.com with SMTP id d9443c01a7336-20688fbaeafso6109515ad.0
        for <kasan-dev@googlegroups.com>; Wed, 18 Sep 2024 23:23:11 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWhl+BgePXtkQtbrAJH0oqvA43t+LmR0ULmYUjMAtGGQ70GMZO8kMxPJu1aQzcIJIg4LYW7c6HXBHc=@googlegroups.com
X-Received: by 2002:a17:902:e84a:b0:1fb:57e7:5bb4 with SMTP id d9443c01a7336-20782a69aa5mr302633235ad.37.1726726990257;
        Wed, 18 Sep 2024 23:23:10 -0700 (PDT)
Received: from dw-tp ([171.76.85.129])
        by smtp.gmail.com with ESMTPSA id d9443c01a7336-207946fcad2sm73406885ad.211.2024.09.18.23.23.05
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 18 Sep 2024 23:23:09 -0700 (PDT)
From: Ritesh Harjani (IBM) <ritesh.list@gmail.com>
To: Christophe Leroy <christophe.leroy@csgroup.eu>, linuxppc-dev@lists.ozlabs.org,
Cc: Michael Ellerman <mpe@ellerman.id.au>, Nicholas Piggin <npiggin@gmail.com>, Madhavan Srinivasan <maddy@linux.ibm.com>, Hari Bathini <hbathini@linux.ibm.com>, "Aneesh Kumar K . V" <aneesh.kumar@kernel.org>, Donet Tom <donettom@linux.vnet.ibm.com>, Pavithra Prakash <pavrampu@linux.vnet.ibm.com>, Nirjhar Roy <nirjhar@linux.ibm.com>, LKML <linux-kernel@vger.kernel.org>, kasan-dev@googlegroups.com, Disha Goel <disgoel@linux.ibm.com>, Alexander Potapenko <glider@google.com>
Subject: Re: [RFC v2 02/13] powerpc: mm: Fix kfence page fault reporting
In-Reply-To: <65664ab8-4250-47c2-be50-d56c112a17fb@csgroup.eu>
Date: Thu, 19 Sep 2024 11:17:16 +0530
Message-ID: <87ldzotct7.fsf@gmail.com>
References: <cover.1726571179.git.ritesh.list@gmail.com> <87095ffca1e3b932c495942defc598907bf955f6.1726571179.git.ritesh.list@gmail.com> <65664ab8-4250-47c2-be50-d56c112a17fb@csgroup.eu>
MIME-version: 1.0
Content-type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: ritesh.list@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=OfGuLZ0t;       spf=pass
 (google.com: domain of ritesh.list@gmail.com designates 2607:f8b0:4864:20::636
 as permitted sender) smtp.mailfrom=ritesh.list@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

Christophe Leroy <christophe.leroy@csgroup.eu> writes:

> Le 19/09/2024 =C3=A0 04:56, Ritesh Harjani (IBM) a =C3=A9crit=C2=A0:
>> copy_from_kernel_nofault() can be called when doing read of /proc/kcore.
>> /proc/kcore can have some unmapped kfence objects which when read via
>> copy_from_kernel_nofault() can cause page faults. Since *_nofault()
>> functions define their own fixup table for handling fault, use that
>> instead of asking kfence to handle such faults.
>>=20
>> Hence we search the exception tables for the nip which generated the
>> fault. If there is an entry then we let the fixup table handler handle t=
he
>> page fault by returning an error from within ___do_page_fault().
>
> Searching the exception table is a heavy operation and all has been done=
=20
> in the past to minimise the number of times it is called, see for=20
> instance commit cbd7e6ca0210 ("powerpc/fault: Avoid heavy=20
> search_exception_tables() verification")

This should not cause latency in user page fault paths. We call
search_exception_tables() only when there is a page fault for kernel
address (which isn't that common right) which otherwise kfence will handle.

>
> Also, by trying to hide false positives you also hide real ones. For=20

I believe these should be false negatives. If kernel functions provides an
exception table to handle such a fault, then shouldn't it be handled via
fixup table provided rather then via kfence?

> instance if csum_partial_copy_generic() is using a kfence protected=20
> area, it will now go undetected.

I can go and look into usages of csum_partial_copy_generic(). But can
you please expand more here on what you meant?=20

... so if a fault occurs for above case, this patch will just let the
fixup table handle that fault rather than kfence reporting it and
returning 0.


The issue we see here is when unmapped kfence addresses get accessed via
*_nofault() variants which causes kfence to report a false negative
(this happens when we use read /proc/kcore or tools like perf read that)

This is because as per my understanding copy_from_kernel_nofault()
should return -EFAULT from it's fixup table if a fault occurs...
whereas with kfence it will report the warning and will return 0 after
kfence handled the fault.

I see other archs too calling fixup_table() in their fault handling
routine before allowing kfence to handle the fault.=20

>
> IIUC, here your problem is limited to copy_from_kernel_nofault(). You=20
> should handle the root cause, not its effects. For that, you could=20
> perform additional verifications in copy_from_kernel_nofault_allowed().

Sorry, why make copy_from_kernel_nofault() as a special case for powerpc?
I don't see any other arch making copy_from_kernel_nofault() as a
special case. Shouldn't Kernel faults be handled via fixup_table(), if
it is supplied, before kfence handling it?
(maybe I am missing something)


-ritesh

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/87ldzotct7.fsf%40gmail.com.
