Return-Path: <kasan-dev+bncBCS37NMQ3YHBBQ7B5P4QKGQECOMQHBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33d.google.com (mail-wm1-x33d.google.com [IPv6:2a00:1450:4864:20::33d])
	by mail.lfdr.de (Postfix) with ESMTPS id 44180247876
	for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 23:04:04 +0200 (CEST)
Received: by mail-wm1-x33d.google.com with SMTP id q15sf6460496wmj.6
        for <lists+kasan-dev@lfdr.de>; Mon, 17 Aug 2020 14:04:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597698244; cv=pass;
        d=google.com; s=arc-20160816;
        b=fKRyESv5mPraztw6SEakERqsRuUQfLVUtqlNdN2orNF8O5imcYiYcEF6t9g9L5EaqQ
         zro75tO4PxsSUd3tzQczukcIHcA+fZKHLpeBF0i3b0OYu1NkkfFDaejUKMYYXHRgB/Bi
         7hr6AXVa6nZSEkBEp1W/5kjG3+s2Xp3BtsGajCzcBSKUG+cXnd9hjX6hTBXxX9N1SJSX
         R5/H61+GjAzd7q9RL/DsPxw6/u31xAdciEV/Ns96F6abGBP3xnYE8KCbNDeNnwMyoLiE
         SIZv/Gnq2NILVV8122nnmFlOi9a7gxyLg4vELOwz25SMfRXVEvzkcIVa/TTBfq9kiCIq
         cK5w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-language:in-reply-to
         :mime-version:user-agent:date:message-id:autocrypt:from:references
         :cc:to:subject:reply-to:sender:dkim-signature;
        bh=MMuiBfxzj6F9HKQT7yO0ibUOyqfrQj50g38aSI3g+vY=;
        b=SZ2wg86UKb1iL2d8t3OrQSCAhCG2DYJElJVcEGBFNzi1P8R3TD2h1pYGHy/iIDmjsz
         krcTub774ELxhdmeIsK/jw9WHto2KshypocMlojsNkmeX1vwcF2b2pJjhaJDBX2eCFcR
         WH3vMKJog7Vi/zd76WM0jVZoUmiui7aYaj/mWy1wrKP3gBLI1CfYTnV8Sg5QGBTZnXZx
         PzJoy3pYXfm+VpR8M32J1nC2ZXLBfiB1/Gm71APO96C077cX93Y6a9sF0woP36v/Mrwi
         v0KOF24KAQNwOUkWr3la3B4V4vH+5Izpk0xzAiwlVZetsOqZd5UFUaPjtcCq4UdHcnem
         +PUA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:reply-to:subject:to:cc:references:from:autocrypt:message-id
         :date:user-agent:mime-version:in-reply-to:content-language
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMuiBfxzj6F9HKQT7yO0ibUOyqfrQj50g38aSI3g+vY=;
        b=DzHgamFObAaDQNOLqItta5O9pyDCF8OxHG/z6V/5ocgSqKX4FHLLIYrGDQFM9iUwms
         bKa37Fo8TCVf1x2BPvUlUZACDlb0az/ii7x43IwDWcx0ODKLa2CoIp4PxuIHaptYqnQY
         X84x8Vxn2iAbS/Ow7tj9vg0lRkLM+JSvaev5E1WrdJhN8Hkfn/lalJGy4grKq8CdWEH+
         RfCj8wNy+LATdL3di5NPfxljCW3XO01L1Im0CEvqggmGbRfzsHSswK5pfNL8Nnvl9JPV
         YCzZ0phfvdxb+lF5HqFKgcr7djfCMI51PtrmY+Yz9K21l99GnoWafbs+QDpf4Pur45JJ
         9RCA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:reply-to:subject:to:cc:references:from
         :autocrypt:message-id:date:user-agent:mime-version:in-reply-to
         :content-language:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=MMuiBfxzj6F9HKQT7yO0ibUOyqfrQj50g38aSI3g+vY=;
        b=ZrWL1s4pMBGKZbSI+YYnHJtJa2NA++T26UtI3ITjPYNPF4kCia/igNnuxxmsBrPuGE
         Ff2Sp/UyJ45XP+gh8L1csLSNNbHvGjUdOwUrqWPw1D1znBdbYF9w0JIsqswDxYqKi84T
         bnYrTzgSlH213O/h8UDd56RgHuZi8W4mWAIb8VlUDXXl77Z2SIQ5z+H3PuScGjXgPvMg
         ZOS11xvT3K/TaCywa6Exwnrm2xytzXdtCC6oMnLB3KkvBpW9Fia7e1eArmOog/TYDyEZ
         /ssMcVml1CPLW1jpP59H70TAHBo9u/hkMmk82nQNJXM7EnftnYL0V3Ay8b55Iq83BjTW
         UMgQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532ZRraqSLcySBrzWCjjNfigf2rjbSwJQBbiAwSHvCGjctjy58aK
	yavYYAIqKFtkHWelNFH90+Q=
X-Google-Smtp-Source: ABdhPJxxdAtC9u2pCmpvE7gyhJAKWVRElJzpGKJCT3I6/UwnBXcUvkHP+p7ypG7+3INknApdBikVaw==
X-Received: by 2002:a1c:80c1:: with SMTP id b184mr17178631wmd.121.1597698244013;
        Mon, 17 Aug 2020 14:04:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a1c:804f:: with SMTP id b76ls94947wmd.2.gmail; Mon, 17 Aug
 2020 14:04:03 -0700 (PDT)
X-Received: by 2002:a1c:de41:: with SMTP id v62mr17083406wmg.163.1597698243271;
        Mon, 17 Aug 2020 14:04:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597698243; cv=none;
        d=google.com; s=arc-20160816;
        b=AjyHKooipndrYm+VKsONTuUirFCqLuJ1hcBsZIYs8PuJBG825SoPCkZ5hf6L0YqcET
         1RWKMth9PEIVtATU88cVxik5ZnMmrpBzp1L2yYl5avuaQTdVlILOr8lOPDKA0oK5bfcZ
         G8O/Fq6IJBQN0bm06qpTVI3cvK5Y4hDz8RE9xG0NXsWPxcVNn0RuymYc/6a+TxdUzScc
         7aaCXl5G24N/ds9JeBX7oYyAXNU7h9dECGhXSwD7oADVCg3S0aEnutzN2Uef3dTwVumB
         MAz7xRMFaWIRNIOhAbjcB5C1jB81hYU0jJXPGr3aY+0bUMrG+82fs3g6fWIqf89ixpe8
         9usg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:content-language:in-reply-to:mime-version
         :user-agent:date:message-id:autocrypt:from:references:cc:to:subject
         :reply-to;
        bh=NBhHzgcaB0DndO5Bo1sbERPDqEvBm+Tpg5B38O5FP9Y=;
        b=lzWFnATZDIG9mRai0bjcgljMXDjYJc4/yerspUntxBe34apS0v9KoxC6fEM7z8kojx
         AciqVlNnz2qoQ2edq4qOxnqqibm587plT85DeGdAJVTRYyOPWWqdiJZvNLp9Y5UEIqhN
         mB1L1+bIaLjI9yMB/ge+1Q/9gA7BYK2pZM/q2/U0OhgGeO7lElzQf61IvRmBx5s554om
         PlSluYJ8kTL1YC3GAwEdNfcGk8Tf4v9fcCtXm6MzJ6r+ajgwg04KYauyqVq8/gKrWhD7
         D0GYFzCY2yX7sIW6PcuZ1eE3WkTgGvrwncgp+fnRGieN3KsWvvy7Wy8lk91UBXaiGDpK
         S6nw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.67 as permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
Received: from mail-ej1-f67.google.com (mail-ej1-f67.google.com. [209.85.218.67])
        by gmr-mx.google.com with ESMTPS id m3si822595wme.0.2020.08.17.14.04.03
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 14:04:03 -0700 (PDT)
Received-SPF: pass (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.67 as permitted sender) client-ip=209.85.218.67;
Received: by mail-ej1-f67.google.com with SMTP id o23so19540875ejr.1
        for <kasan-dev@googlegroups.com>; Mon, 17 Aug 2020 14:04:03 -0700 (PDT)
X-Received: by 2002:a17:906:4f8c:: with SMTP id o12mr17336022eju.69.1597698243014;
        Mon, 17 Aug 2020 14:04:03 -0700 (PDT)
Received: from [10.9.0.18] ([185.248.161.177])
        by smtp.gmail.com with ESMTPSA id qp16sm15127035ejb.89.2020.08.17.14.03.58
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 17 Aug 2020 14:04:02 -0700 (PDT)
Reply-To: alex.popov@linux.com
Subject: Re: [PATCH RFC 1/2] mm: Extract SLAB_QUARANTINE from KASAN
To: Pavel Machek <pavel@denx.de>, Matthew Wilcox <willy@infradead.org>
Cc: Kees Cook <keescook@chromium.org>, Jann Horn <jannh@google.com>,
 Will Deacon <will@kernel.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
 Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
 Christoph Lameter <cl@linux.com>, Pekka Enberg <penberg@kernel.org>,
 David Rientjes <rientjes@google.com>, Joonsoo Kim <iamjoonsoo.kim@lge.com>,
 Andrew Morton <akpm@linux-foundation.org>,
 Masahiro Yamada <masahiroy@kernel.org>,
 Masami Hiramatsu <mhiramat@kernel.org>, Steven Rostedt
 <rostedt@goodmis.org>, Peter Zijlstra <peterz@infradead.org>,
 Krzysztof Kozlowski <krzk@kernel.org>,
 Patrick Bellasi <patrick.bellasi@arm.com>,
 David Howells <dhowells@redhat.com>, Eric Biederman <ebiederm@xmission.com>,
 Johannes Weiner <hannes@cmpxchg.org>, Laura Abbott <labbott@redhat.com>,
 Arnd Bergmann <arnd@arndb.de>,
 Greg Kroah-Hartman <gregkh@linuxfoundation.org>, kasan-dev@googlegroups.com,
 linux-mm@kvack.org, kernel-hardening@lists.openwall.com,
 linux-kernel@vger.kernel.org, notify@kernel.org,
 Andrey Konovalov <andreyknvl@google.com>
References: <20200813151922.1093791-1-alex.popov@linux.com>
 <20200813151922.1093791-2-alex.popov@linux.com>
 <20200815185455.GB17456@casper.infradead.org> <20200816195930.GA4155@amd>
From: Alexander Popov <alex.popov@linux.com>
Autocrypt: addr=alex.popov@linux.com; prefer-encrypt=mutual; keydata=
 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
 j3lCqPk=
Message-ID: <c6d3b4ce-cdb1-4bc9-d899-89228b4219cd@linux.com>
Date: Tue, 18 Aug 2020 00:03:57 +0300
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101
 Thunderbird/68.10.0
MIME-Version: 1.0
In-Reply-To: <20200816195930.GA4155@amd>
Content-Type: text/plain; charset="UTF-8"
Content-Language: en-US
X-Original-Sender: a13xp0p0v88@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of a13xp0p0v88@gmail.com designates 209.85.218.67 as
 permitted sender) smtp.mailfrom=a13xp0p0v88@gmail.com
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

On 16.08.2020 22:59, Pavel Machek wrote:
> On Sat 2020-08-15 19:54:55, Matthew Wilcox wrote:
>> On Thu, Aug 13, 2020 at 06:19:21PM +0300, Alexander Popov wrote:
>>> +config SLAB_QUARANTINE
>>> +	bool "Enable slab freelist quarantine"
>>> +	depends on !KASAN && (SLAB || SLUB)
>>> +	help
>>> +	  Enable slab freelist quarantine to break heap spraying technique
>>> +	  used for exploiting use-after-free vulnerabilities in the kernel
>>> +	  code. If this feature is enabled, freed allocations are stored
>>> +	  in the quarantine and can't be instantly reallocated and
>>> +	  overwritten by the exploit performing heap spraying.
>>> +	  This feature is a part of KASAN functionality.
>>
>> After this patch, it isn't part of KASAN any more ;-)
>>
>> The way this is written is a bit too low level.  Let's write it in terms
>> that people who don't know the guts of the slab allocator or security
>> terminology can understand:
>>
>> 	  Delay reuse of freed slab objects.  This makes some security
>> 	  exploits harder to execute.  It reduces performance slightly
>> 	  as objects will be cache cold by the time they are reallocated,
>> 	  and it costs a small amount of memory.
> 
> Written this way, it invites questions:
> 
> Does it introduce any new deadlocks in near out-of-memory situations?

Linux kernel with enabled KASAN is heavily tested by syzbot.
I think Dmitry and Andrey can give good answers to your question.

Some time ago I was doing Linux kernel fuzzing with syzkaller on low memory
virtual machines (with KASAN and LOCKUP_DETECTOR enabled). I gave less than 1G
to each debian stretch VM. I didn't get any special deadlock caused by OOM.

Best regards,
Alexander

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/c6d3b4ce-cdb1-4bc9-d899-89228b4219cd%40linux.com.
