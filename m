Return-Path: <kasan-dev+bncBAABBWWR5XEAMGQENPSONHQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 31398C65B59
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 19:26:36 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-37a2d8cc3d3sf29106221fa.0
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Nov 2025 10:26:36 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1763403995; cv=pass;
        d=google.com; s=arc-20240605;
        b=YxEVDePAHBBmcB4lgo21/xI/BK4GCNpC6qJJfH8IX5579BnRPGfbP4V0ZzcW0exRr3
         HIAo4JdzbFCMxeLh3bUh4mXUDor1jCuxDjK0K73fYWe6KimvqcXt/W7XoAM91N2rXMZF
         gPVae3mX0b8D6RE6SwirfrBLR9NI5IuzKfo1UcRPA5PY0JqlqdKCYLsiNkz0XQG/nV8A
         onnKB6OINI0EdZOKxmuC2M/PdyaTO0lWBMSPwMWawxo2BqB06/mvCUqCYHDO7L431R7A
         x5YQZ3oi1Sy682eEc/TWlE+62XnIUKAtlXI/r/X4+QJcqXRSKncBB5+oFx9p6aESTji+
         iMjw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version:feedback-id
         :references:in-reply-to:message-id:subject:cc:from:to:date
         :dkim-signature;
        bh=XZdwyharRiyY6pi6Nbk2bC6NWEFNwi69s2U2dkvS1MQ=;
        fh=sJVprHedjwwh6iBlZZJH+H1moCN1+fO8Sb3WNRf3PzQ=;
        b=XGdKHiASAyHLM+HxiIo4BtdU+qjCKB/01fff2xRC2pLSt9PljCqwpXFoyDlaxFrVX0
         D8rZP7hrYIKT1/6e9fAK2QOvCV/p3MkDcuAyoRTVEJj7HW7nhKdYeuzckQ/TfwfuUYgU
         xBaMB0TtqflL+bPhOquJxIlDZoCeNpVX0hfvGfylLgH0IoJZqxsUQIO/S5JNxXn9PZce
         ULkorQpX6F/x3adJsSEqAKQgT0t11SP/iK8XqYSMg/1a0ub6zpiHPfXueg7TvSnR1nf2
         X3K+p9e3ytABD44BfZnSCMmm3s4U7mupQzTgQdVaqJmBP9gr25jYGaKHbgTjWvdoTbD7
         Hh6w==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BmWBhb8y;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1763403995; x=1764008795; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:from:to:cc:subject:date:message-id:reply-to;
        bh=XZdwyharRiyY6pi6Nbk2bC6NWEFNwi69s2U2dkvS1MQ=;
        b=q0WKfr/KoVMecIRUFOb79rvhfO8EBdy+CxcQjX1FOVUu7bR7KXOof+9UvPGx+JTQws
         84mwCip4Egnu0+uVcq66s8YO/OuftNB3H7mKlPyNdXTZskPOtpXuutbS7N2wMyzd3wgt
         LK2pTdnmhPyZ66+/SCtRhPeaRD+2ap7GCzEpJqnzXTYhx7DwOvYzSZna2eeR2JcY1wA8
         cDmladzfgMY1mZomNXgRsLMhFnc/oB/DsiQuLUFmIg27rnTL/JldF3KLceko/DNN9lVX
         f5cTBM7uLdrIsByFyrK08Ck05oLEBrsKUpl5TOTvXzVK9nCxfO2h6NeGVidm0E6SZRce
         M5hA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1763403995; x=1764008795;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :feedback-id:references:in-reply-to:message-id:subject:cc:from:to
         :date:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=XZdwyharRiyY6pi6Nbk2bC6NWEFNwi69s2U2dkvS1MQ=;
        b=HfFL8MzY7Jhfq4B0QNyYBUe23S65MiQJ3+aP9Xb2yRWuEVXM/lTzRXsToEdgMQY/t6
         exYAkJOmncODv+Dy/FoExnoV875b2XveVA9Bm4gudXmg1VP1KHAnKVwNBD8ZFNmm8JEi
         3c6O8n3GsO5ZU54KvEppKr8rEb+PGmRsdIgnCI2yOBzh4Z8at+zIiv/B0HlroR/FIOgW
         Ck0yak0BeLVim+D3gmalNH5nR7clEShKSHIOw4jHmRKNwJZj6vV61zVa9cBlm5BidUlN
         txfMZbZiWbH+NAFeGBQBXtYWDaDDzoizPTnf3o2vytIx4xURBRrNyj2aDzYc1ler1TkU
         beeA==
X-Forwarded-Encrypted: i=2; AJvYcCW3LWkbJjzBIcLX4XRxKhRXuCfx/Va1DmEq2AgXgslhU/GD2g0izul+jhiUV0BqfSITp0OpcQ==@lfdr.de
X-Gm-Message-State: AOJu0YzK9HNkmTzujmB6fWtjQ+MI7bPEZtT2moJqiuIne9OVdUikp0fQ
	lU6X0qPvf4DpvxCTR1xmdE1ihkSmamoNdzHJffxRU92yLyIK0H0pwPOT
X-Google-Smtp-Source: AGHT+IF5Fvz79lvgGw1M9HrehnMQTSxay4WHNGl73yBXhNfu4MVwaPPg5yzskSqcaJia5aYKs8VW1g==
X-Received: by 2002:a2e:ab87:0:b0:37b:9361:711d with SMTP id 38308e7fff4ca-37bc7d59d16mr938581fa.8.1763403995115;
        Mon, 17 Nov 2025 10:26:35 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h="Ae8XA+aXvPTjjyAkEzX2l4SH79fM3SQheox8wOzufsrgwKvk3g=="
Received: by 2002:a2e:8692:0:b0:37a:2f0c:a75c with SMTP id 38308e7fff4ca-37b9ab1e260ls5788971fa.2.-pod-prod-00-eu;
 Mon, 17 Nov 2025 10:26:33 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCWMIOj2RCtyh1CBcvjNklu/tTHclScGGcGN+VOcjIahlID6YYtVI0URX3LLo4L+XlYtHjjfaHF/low=@googlegroups.com
X-Received: by 2002:a2e:a009:0:10b0:364:c083:2fec with SMTP id 38308e7fff4ca-37bc7d5d66fmr731861fa.7.1763403992717;
        Mon, 17 Nov 2025 10:26:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1763403992; cv=none;
        d=google.com; s=arc-20240605;
        b=Q9k5De6KHvSJQWihxHAPt/007nK49pcbYUs14MsPezCncY4+UFxTf7dU/i+PARFKFH
         fLr2wtd9ejybugAIyVwNHPZiUf+whQvQtYFhMRknK6p0DWMA4eqUDVQbPmhYneCL2wFZ
         0wogKJ90jZ+uwnDqVTUgCJJFApo9cjRi4pA8CGIfFjHWSg6G0ecPnL4f7INCfJ4G/qY8
         C/xbQTo9uXEDOydn+EJCxHCnaEgGmtppjpCyJAdd9QfZ7fS5BZdQhjq+/aUx5784A3RL
         8hl0ovebC9OopMw8YfXa2fqmMjSQUK7NWXScQACSQo/IwtIGsighnGCjnIeMIKb0L8Sn
         cTnw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:mime-version:feedback-id:references
         :in-reply-to:message-id:subject:cc:from:to:date:dkim-signature;
        bh=jouESHi5Un7Q4FQfUgenF4mt4d6TLFLTX4D6FWFBOHM=;
        fh=KsJA6GCCEvvBxA5wQjLnziA2O1XGvHwmGGh7iMVS7jQ=;
        b=bjpdqHHDP+1bbQZDtR1LyoD2VwoJ04uaara1lpJvw7ezZ0rGYz2Y6+LzltBtTZq4mH
         A0/cnHdxgkT/Te94swW7IlfdV8K0K+dsXHTLYlWNZXATzkpTR5wJF1KEVgXdHWplNxIW
         44VcnETlODuYUVIWNG4A8OGdy/PJQ1J8HtJkfQICRHLV+bP8MenmXlw3rMhsaBch/cOa
         /JAxiJ8fqPNKAEQek0uo3RIGpt0f2rSq0kvDl366aTiyNNu5NjyxMMpApsgzLRgKLszg
         PfUMImlWM1S8w0DOZMcfpZfg8SodSWUFuKrM/qt2FTQf7qen+rplS0+sjEEbuvewgHXp
         1rJg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@pm.me header.s=protonmail3 header.b=BmWBhb8y;
       spf=pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
Received: from mail-4316.protonmail.ch (mail-4316.protonmail.ch. [185.70.43.16])
        by gmr-mx.google.com with ESMTPS id 38308e7fff4ca-37b9cb7e438si2301191fa.0.2025.11.17.10.26.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 17 Nov 2025 10:26:32 -0800 (PST)
Received-SPF: pass (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as permitted sender) client-ip=185.70.43.16;
Date: Mon, 17 Nov 2025 18:26:19 +0000
To: Marco Elver <elver@google.com>
From: =?UTF-8?Q?=27Maciej_Wiecz=C3=B3r=2DRetman=27_via_kasan=2Ddev?= <kasan-dev@googlegroups.com>
Cc: xin@zytor.com, peterz@infradead.org, kaleshsingh@google.com, kbingham@kernel.org, akpm@linux-foundation.org, nathan@kernel.org, ryabinin.a.a@gmail.com, dave.hansen@linux.intel.com, bp@alien8.de, morbo@google.com, jeremy.linton@arm.com, smostafa@google.com, kees@kernel.org, baohua@kernel.org, vbabka@suse.cz, justinstitt@google.com, wangkefeng.wang@huawei.com, leitao@debian.org, jan.kiszka@siemens.com, fujita.tomonori@gmail.com, hpa@zytor.com, urezki@gmail.com, ubizjak@gmail.com, ada.coupriediaz@arm.com, nick.desaulniers+lkml@gmail.com, ojeda@kernel.org, brgerst@gmail.com, pankaj.gupta@amd.com, glider@google.com, mark.rutland@arm.com, trintaeoitogc@gmail.com, jpoimboe@kernel.org, thuth@redhat.com, pasha.tatashin@soleen.com, dvyukov@google.com, jhubbard@nvidia.com, catalin.marinas@arm.com, yeoreum.yun@arm.com, mhocko@suse.com, lorenzo.stoakes@oracle.com, samuel.holland@sifive.com, vincenzo.frascino@arm.com, bigeasy@linutronix.de, surenb@google.com, ardb@kernel.org,
	Liam.Howlett@oracle.com, nicolas.schier@linux.dev, ziy@nvidia.com, kas@kernel.org, tglx@linutronix.de, mingo@redhat.com, broonie@kernel.org, corbet@lwn.net, andreyknvl@gmail.com, maciej.wieczor-retman@intel.com, david@redhat.com, maz@kernel.org, rppt@kernel.org, will@kernel.org, luto@kernel.org, kasan-dev@googlegroups.com, linux-kernel@vger.kernel.org, linux-arm-kernel@lists.infradead.org, x86@kernel.org, linux-kbuild@vger.kernel.org, linux-mm@kvack.org, llvm@lists.linux.dev, linux-doc@vger.kernel.org
Subject: Re: [PATCH v6 17/18] x86/kasan: Logical bit shift for kasan_mem_to_shadow
Message-ID: <jbmfvznqtzmeyejegflmznwfj7lzlshpmek7jgy7drjfla2btb@bqjufhxforw2>
In-Reply-To: <CANpmjNM+ot5A-pRLhV6Esn=QvCeCStd9fG_pgwrVA=6pxD8aqw@mail.gmail.com>
References: <cover.1761763681.git.m.wieczorretman@pm.me> <81848c9df2dc22e9d9104c8276879e6e849a5087.1761763681.git.m.wieczorretman@pm.me> <CANpmjNM+ot5A-pRLhV6Esn=QvCeCStd9fG_pgwrVA=6pxD8aqw@mail.gmail.com>
Feedback-ID: 164464600:user:proton
X-Pm-Message-ID: 8d14ced91bdd2f91cd367e805c79e65e22e0506e
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: m.wieczorretman@pm.me
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@pm.me header.s=protonmail3 header.b=BmWBhb8y;       spf=pass
 (google.com: domain of m.wieczorretman@pm.me designates 185.70.43.16 as
 permitted sender) smtp.mailfrom=m.wieczorretman@pm.me;       dmarc=pass
 (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=pm.me
X-Original-From: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
Reply-To: =?utf-8?Q?Maciej_Wiecz=C3=B3r-Retman?= <m.wieczorretman@pm.me>
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

On 2025-11-10 at 15:49:22 +0100, Marco Elver wrote:
>On Wed, 29 Oct 2025 at 21:11, Maciej Wieczor-Retman
><m.wieczorretman@pm.me> wrote:
>>
>> From: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>>
>> While generally tag-based KASAN adopts an arithemitc bit shift to
>> convert a memory address to a shadow memory address, it doesn't work for
>> all cases on x86. Testing different shadow memory offsets proved that
>> either 4 or 5 level paging didn't work correctly or inline mode ran into
>> issues. Thus the best working scheme is the logical bit shift and
>> non-canonical shadow offset that x86 uses for generic KASAN, of course
>> adjusted for the increased granularity from 8 to 16 bytes.
>>
>> Add an arch specific implementation of kasan_mem_to_shadow() that uses
>> the logical bit shift.
>>
>> The non-canonical hook tries to calculate whether an address came from
>> kasan_mem_to_shadow(). First it checks whether this address fits into
>> the legal set of values possible to output from the mem to shadow
>> function.
>>
>> Tie both generic and tag-based x86 KASAN modes to the address range
>> check associated with generic KASAN.
>>
>> Signed-off-by: Maciej Wieczor-Retman <maciej.wieczor-retman@intel.com>
>> ---
>> Changelog v4:
>> - Add this patch to the series.
>>
>>  arch/x86/include/asm/kasan.h | 7 +++++++
>>  mm/kasan/report.c            | 5 +++--
>>  2 files changed, 10 insertions(+), 2 deletions(-)
>>
>> diff --git a/arch/x86/include/asm/kasan.h b/arch/x86/include/asm/kasan.h
>> index 375651d9b114..2372397bc3e5 100644
>> --- a/arch/x86/include/asm/kasan.h
>> +++ b/arch/x86/include/asm/kasan.h
>> @@ -49,6 +49,13 @@
>>  #include <linux/bits.h>
>>
>>  #ifdef CONFIG_KASAN_SW_TAGS
>> +static inline void *__kasan_mem_to_shadow(const void *addr)
>> +{
>> +       return (void *)((unsigned long)addr >> KASAN_SHADOW_SCALE_SHIFT)
>> +               + KASAN_SHADOW_OFFSET;
>> +}
>
>You're effectively undoing "kasan: sw_tags: Use arithmetic shift for
>shadow computation" for x86 - why?
>This function needs a comment explaining this.

Sure, I'll add a comment here.

While the signed approach seems to work well for arm64 and risc-v it
doesn't play well with x86 which wants to keep the top bit for
canonicality checks.

Trying to keep signed mem to shadow scheme for all corner cases on all
configs always turned into ugly workarounds for something. There is a
mechanism, when there is a fault, to guess if the address came from a
KASAN check - some address format always didn't work when I tried
validating 4 and 5 paging levels. One approach to getting the signed mem
to shadow was also using a non-canonial kasan shadow offset. It worked
great for paging as far as I remember (some 5 lvl fixup code could be
removed) but it made the inline mode either hard to implement or much
slower due to extended checks.

>Also, the commit message just says "it doesn't work for all cases" - why?

Fair enough, this was a little not verbose. I'll update the patch
message with an explanation.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/jbmfvznqtzmeyejegflmznwfj7lzlshpmek7jgy7drjfla2btb%40bqjufhxforw2.
