Return-Path: <kasan-dev+bncBCQ2XPNX7EOBB6P65X6AKGQEJAKHTXI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23a.google.com (mail-lj1-x23a.google.com [IPv6:2a00:1450:4864:20::23a])
	by mail.lfdr.de (Postfix) with ESMTPS id 3486529FBB8
	for <lists+kasan-dev@lfdr.de>; Fri, 30 Oct 2020 03:50:34 +0100 (CET)
Received: by mail-lj1-x23a.google.com with SMTP id i3sf2094216lja.15
        for <lists+kasan-dev@lfdr.de>; Thu, 29 Oct 2020 19:50:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1604026233; cv=pass;
        d=google.com; s=arc-20160816;
        b=DRmhgHggvZYZUuR/L+fjG20GV/Y788uTbD5DhtxBl74H+CzwqBn5Nnt6+aL2+hdAsg
         8PGN2pGWKsrNG/bXYppkY4kN3KJvFa1bOhVEiHV/wibXN5duiSG9cIY8rgupcNlWPmd/
         aqU5edq6Iz3JbD7MxWwEuRNTU4mf6CEvKp43A4jrJ+FHCecXzvMBCboIbVlhND10KnNq
         2THqf7/JNXXsM8nu2UsQlCUhEetkTAFptW3XLhCqOqXPjGtu4799O4kFbY/d/9h4YCtr
         Cz0h6ge6y610Sl9+F2SC4zECaBApZoA11wTaaw5ziDf7JdID+Qzl01E35FkfOVRDJ7BI
         FqGQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=qg+RwMGPB3cILXjhYfKja5u99ypcv2oxOqD9asy/jnc=;
        b=wQlciy5dBFKFYADwhppUGVJ5lurDN5RqIwiLtb1JRKuEppf4DlmzlnvaRN7vkmM4nB
         2+Aq990Vi1xCjGMYSGdbU0kTsU8AFUMa8n1LKHEd0QDOFEtfOUMADekf6bVJKY1uDMxB
         JLltUBhDPmgcsZ8LCCoHquBlAkaRTh9XI6HXZsnxOtxeugiM5Fe5f/xg2Hlsxaj6WzCI
         9LxuoBhGbgR02A/lV2o2PzVH4QQu7/P43ehYJTjCc5V5OOOvjD+lJ+Ff+hrX3LcI5tQ4
         4kzBRu6lWahScNztXyWkdpxgK2CgGtQkAOWHW7AWUk7Xu5QZN+bpNFd9diDwffaYskSx
         je8Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UCfTk7uM;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qg+RwMGPB3cILXjhYfKja5u99ypcv2oxOqD9asy/jnc=;
        b=mzefDgzV+DWiP927CAkdODNBW4k2Ry9FrPLaxK2C6oSwRlzB2H4Apm9sBoE9eDBHnu
         coaKnfekMJ/8UwPBUURKWTzCpJhzyyAhjWqyDkekI9Zuw48X3udqKm++kIHvHB/UelzG
         LyUr9rYISdplSi92LrnmKqb9VPDJ2sCzmvta0UepgHhglFx+kMqM1MMdKeRS6mwafRRv
         Bjc6LYPXwIZssumvOl5FspdM4m8EsV0QkX6g45dB+zrQo9pmhNP9obwvJMe/NahMZJMH
         iljy8Kdd+sGxSUVmwMaLk7+uK2Kj9ukZ851HoIojMS2Vaut43KSMsa4zPfE5H1vJQh7P
         FDCw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=qg+RwMGPB3cILXjhYfKja5u99ypcv2oxOqD9asy/jnc=;
        b=YRmew7Vz2dkfwp0Y2VJEsBKSuZIa86dfTm1muZoZrBrV0GUqnKaK/bvoyp2AjtSFME
         Yi6IBDjkBOFGNO2CE4rFWd+/yNeLlAafIbwUURN594AS80eyupK6irtjc30AsUrS7GOq
         vZDptHOmNzPwk+YVgC3HAf/FmoNorUjpdipKC4+XP+8BT9FgyKbRnXlVkhX9v7uuOMCk
         WjXUiW7Cqy1cBHOiHzhc0qbyeDYW+11fJdX/OXOQopIrPHDKH0Kh2pKfk4jhtm88ON+p
         7vie44dPtJNw3nrbaZGlJO/5YYRAx9KvFUiQvYVNaEgfRvyjPgDoamCJ9yJvJdFwFYiv
         jqmg==
X-Gm-Message-State: AOAM531edDn550BLlQUn6L6CMt2m0sJrLLqHqAvo12n1ghjFPF/+g5kz
	fpuJhdWugOqrqwZoS/iiKRw=
X-Google-Smtp-Source: ABdhPJzkukuZdkyRlTkYsh8doywJOSR6WTd2cv+K1B8o8JteeyvY7G9VEfEovMtsrWvPoYMUEVGBXw==
X-Received: by 2002:a2e:8e8f:: with SMTP id z15mr108936ljk.238.1604026233812;
        Thu, 29 Oct 2020 19:50:33 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b016:: with SMTP id y22ls908933ljk.3.gmail; Thu, 29 Oct
 2020 19:50:32 -0700 (PDT)
X-Received: by 2002:a2e:9bce:: with SMTP id w14mr88060ljj.439.1604026232841;
        Thu, 29 Oct 2020 19:50:32 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1604026232; cv=none;
        d=google.com; s=arc-20160816;
        b=AySJ0/cQuKc2XhJA7DNTDNuk3/p6qaYwPlfPOFx7LJbcjmtf4N0/7OapMt/c4oSCYK
         6c1mzirm8KNhgDJUDMEcxrG4g46o3tRRLLRn6pkFf5QzCR2CLGfhUi2K595cjbwesI1g
         YLMjhjS2jY1brc2KIhPKdzGgcQZqvUbTT/HgMPdjHlQtb/Muv3npj8jjQ31VC8f6qscw
         5LBxOlfDhXisvO2JdHmiipt9+A5nfMhKUFlUFndRbQcXLBTPVmVh9jw30oLbbqnNUNjs
         O9/WEhuvcSDkMqutSS1DvQ8GWi8avlLnfWXeEj8wkwXnDNPoJY4OXScVAcpXvw/Uzl2B
         b7tQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=C030SNL8ytYALn4NBSzKMY+djTDRmDtL+lOw/6SUbHM=;
        b=Zx+JAzHeFCrMytinycNAw4k9FT+STmr0XrEjQOzi6K6VESSBrlenXM5foUcg9PuIsp
         hPXfhz0B7unS1panRtADywDGZ2c+R8NTIzmreC0jK5BcFMQxQqTyQFIkAFNrI6JbcNcT
         Wlswtv04hNCVjMf8tv56ttVue0dygVE87Zl9FQcbL2wp7wTbKVTDIo73LdkKrCGkUvQA
         fo25cyW+ab7rOJ7tdsObXSLp5e2mi6SCKkCRMZIqYBdgTCKxrrWd+CK9QVPo2JCyEu7h
         8K06cAnFpXpFUGTQJZNZia7C3nG7oKsT8bEmMkVsoMWBMlRdVsrJXVx85YXkk7Kl4kGn
         nXFQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=UCfTk7uM;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-lj1-x243.google.com (mail-lj1-x243.google.com. [2a00:1450:4864:20::243])
        by gmr-mx.google.com with ESMTPS id y17si121205lfh.4.2020.10.29.19.50.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 29 Oct 2020 19:50:32 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as permitted sender) client-ip=2a00:1450:4864:20::243;
Received: by mail-lj1-x243.google.com with SMTP id x6so5367067ljd.3
        for <kasan-dev@googlegroups.com>; Thu, 29 Oct 2020 19:50:32 -0700 (PDT)
X-Received: by 2002:a2e:b6cf:: with SMTP id m15mr98951ljo.74.1604026232451;
 Thu, 29 Oct 2020 19:50:32 -0700 (PDT)
MIME-Version: 1.0
References: <20201029131649.182037-1-elver@google.com> <20201029131649.182037-10-elver@google.com>
In-Reply-To: <20201029131649.182037-10-elver@google.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 30 Oct 2020 03:50:05 +0100
Message-ID: <CAG48ez1sfD=Pe9BZRVZK4wpWp9ci91eMrrYus+a4uaactVUVtg@mail.gmail.com>
Subject: Re: [PATCH v6 9/9] MAINTAINERS: Add entry for KFENCE
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Alexander Potapenko <glider@google.com>, 
	"H . Peter Anvin" <hpa@zytor.com>, "Paul E . McKenney" <paulmck@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Andy Lutomirski <luto@kernel.org>, Borislav Petkov <bp@alien8.de>, 
	Catalin Marinas <catalin.marinas@arm.com>, Christoph Lameter <cl@linux.com>, 
	Dave Hansen <dave.hansen@linux.intel.com>, David Rientjes <rientjes@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Eric Dumazet <edumazet@google.com>, 
	Greg Kroah-Hartman <gregkh@linuxfoundation.org>, Hillf Danton <hdanton@sina.com>, 
	Ingo Molnar <mingo@redhat.com>, Jonathan Cameron <Jonathan.Cameron@huawei.com>, 
	Jonathan Corbet <corbet@lwn.net>, Joonsoo Kim <iamjoonsoo.kim@lge.com>, joern@purestorage.com, 
	Kees Cook <keescook@chromium.org>, Mark Rutland <mark.rutland@arm.com>, 
	Pekka Enberg <penberg@kernel.org>, Peter Zijlstra <peterz@infradead.org>, 
	SeongJae Park <sjpark@amazon.com>, Thomas Gleixner <tglx@linutronix.de>, Vlastimil Babka <vbabka@suse.cz>, 
	Will Deacon <will@kernel.org>, "the arch/x86 maintainers" <x86@kernel.org>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, kernel list <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	Linux ARM <linux-arm-kernel@lists.infradead.org>, Linux-MM <linux-mm@kvack.org>, 
	SeongJae Park <sjpark@amazon.de>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=UCfTk7uM;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::243 as
 permitted sender) smtp.mailfrom=jannh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Jann Horn <jannh@google.com>
Reply-To: Jann Horn <jannh@google.com>
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

On Thu, Oct 29, 2020 at 2:17 PM Marco Elver <elver@google.com> wrote:
> Add entry for KFENCE maintainers.
>
> Reviewed-by: Dmitry Vyukov <dvyukov@google.com>
> Reviewed-by: SeongJae Park <sjpark@amazon.de>
> Co-developed-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Alexander Potapenko <glider@google.com>
> Signed-off-by: Marco Elver <elver@google.com>
[...]
> diff --git a/MAINTAINERS b/MAINTAINERS
[...]
> +KFENCE
> +M:     Alexander Potapenko <glider@google.com>
> +M:     Marco Elver <elver@google.com>
> +R:     Dmitry Vyukov <dvyukov@google.com>
> +L:     kasan-dev@googlegroups.com
> +S:     Maintained
> +F:     Documentation/dev-tools/kfence.rst
> +F:     include/linux/kfence.h
> +F:     lib/Kconfig.kfence
> +F:     mm/kfence/

Plus arch/*/include/asm/kfence.h?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAG48ez1sfD%3DPe9BZRVZK4wpWp9ci91eMrrYus%2Ba4uaactVUVtg%40mail.gmail.com.
