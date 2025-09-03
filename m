Return-Path: <kasan-dev+bncBCCMH5WKTMGRBUVA4DCQMGQEANMBEYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id E8818B41AAA
	for <lists+kasan-dev@lfdr.de>; Wed,  3 Sep 2025 11:54:34 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-2445806b18asf74469965ad.1
        for <lists+kasan-dev@lfdr.de>; Wed, 03 Sep 2025 02:54:34 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1756893267; cv=pass;
        d=google.com; s=arc-20240605;
        b=B25/LvysLPEF2fmkYfCxFBfjLAkiYWV43pnL/yTT3dwT6oBUY5kKs1qB8rzFMv22GT
         Zd2Kvmj78L/ltUMcdsdpcUfW163hytQK196ClfNP/Fw9y339IZcr/3z8tBY/drJbGKw4
         Rom7PSceJMrkqZj5a6/o10fkbpvKSOGFYm/I6s3xkLoWtI3Z+UTZIuw932xFLPBiHo1A
         OwrIQNFV3D9JqoWhr9Ni0/5+urTmv7nKTU3vMyXY7yI73FDT4O369nLqtmtuBoCtEeVz
         01edLlhEPWdDq4GDqNVxWTrygiCKF5CfWYuM7sD4Wp6V1X8kWbAgqMQLQ2E28IoewIDp
         CO8w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xCmfZYHCIcX/C/DDu/JAQfKH0MIx+DiJJYT9c8PJjZg=;
        fh=wQe9i0wHkc4hV8DXUmirfG1qpJpC/RLiJsuWWJihYmk=;
        b=RONCT/Z9vhN6m9Xt0CwLcRjeIatNeZWGIdxMCkxeTm9EAELdA0CNBKbCdlZpASPcq3
         Jagzyob6pwG6ocsvJLkIhDV0yN3seZf+EOuV1/wzxgziGhAfRsgJ+HnYA06Tueq0c9eg
         eyFTenFG4ucSuVxdA96qZVUlEh1nJJ1n+QTF8Zp2ZSVecAyEa91H+VDiR1PH0t0vrrrX
         Kkt9bz2Pg65cRWa9VX6bi2RxRLRlLFTBqWuyo5GROsJQaau/LzuopxR03kzvQMCth6LU
         KqykNw5QmW8hyjkfag1X2DQnQpiJpbfUNEz2mZsS4oc6akay9UuqWYuJ5qyC7Ub8TRjI
         eBHA==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D72IoaHb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1756893267; x=1757498067; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=xCmfZYHCIcX/C/DDu/JAQfKH0MIx+DiJJYT9c8PJjZg=;
        b=oh4pmtGaUB4mDmMh7riuy5jQs8iYYBjpfA0mGSkCcwBYTcgBuf38gW7gIwbjbWMoWe
         sNjU8X/fZB3+1XRpo0mxGCb6wmaowc72MXgPMuI/kuJsR0zFfOrxH7abjz8iHFehr7n6
         SfvPeVk/u+FttzB/jopZ6bdKEXuX+zBd3v6Xt4jzqB4TVffRgY5w2K0BZ8f+h6Zj7M4S
         d3pE6nEd09pN/XBQYY50oOHxs9vtGpa9JO5A65pca2Kt/3SR57+meYqH1jC/fdZHTdrP
         1lnrD38GVAVpfp+TGCdIqRvtnM3cd0e2x8uGSqPSd9hJCLxUjClKj0s+jCQS7yUI69qW
         85kg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1756893267; x=1757498067;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=xCmfZYHCIcX/C/DDu/JAQfKH0MIx+DiJJYT9c8PJjZg=;
        b=FBpEWS0KC1nNrsI6GcJQ94yv1TSjl79je5+8zAFlHNEE4/nBjwH/sY183DRZHE2mAS
         y22PflVrDWcsMuQnkKgyAsKOltZyW4jawILPysrHjb+VZM24BILtqaiyVwhaO7EeAMhM
         ql9AvBCzu94QOhhIChrmly/I3gmqKiEg6p0X6gybp90o+1wZUZQ/SLaciRyzKArKRG66
         hCt0WDIeGGbqnuB6w4VXN3mdn7vvYgBogZfOICLegE4+ahb+T+xD3CZqjAGRbCWj5xop
         zWVWPS6TpcC6jayi6dNWXyo81jglA7Nvwut/O7x5QH78U7FMCfOF6KlakM7cVl/s/FtA
         EB/A==
X-Forwarded-Encrypted: i=2; AJvYcCUB0Arr1hennDHgkGV6HQnPEinmDwJeKbEe62qqmjVJhlavsQ1NbN7w9yA5h9XspjbCPOKnpA==@lfdr.de
X-Gm-Message-State: AOJu0YymPnaaFBSf9+BBOp1n6DlrE3LSNV9NGHn7pdvkt7hU8XBTqddh
	vF7DND0ziWUJoCu15X1dqeU03yGCFgmVoexYSHuOsVFoVCbGES6f0/19
X-Google-Smtp-Source: AGHT+IHfCWYbFGn0T2SYHVk0FePTp8uKu0NgssGGlo0yLt/aRs6fzV1mKLOPItjhPvh/VT48QVG6PQ==
X-Received: by 2002:a17:903:19e4:b0:248:db40:daed with SMTP id d9443c01a7336-24944871fc8mr228303565ad.1.1756893266924;
        Wed, 03 Sep 2025 02:54:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcbZzSh8Qj/BhYOFQWKO96YXnVnUb/2G5xXt/y2kAWEOw==
Received: by 2002:a17:902:d094:b0:24b:b55:9343 with SMTP id
 d9443c01a7336-24b0b55a66bls17038915ad.1.-pod-prod-09-us; Wed, 03 Sep 2025
 02:54:25 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCUgGM7wc5Vg6PvIUy663F24WRiTlGKOs4xsV87pu+CNAExPRtXHj7way3jP+kxC1I8YxNzT3JuAZb4=@googlegroups.com
X-Received: by 2002:a17:903:28c:b0:248:811e:f873 with SMTP id d9443c01a7336-24944ab8f4bmr193554205ad.36.1756893265407;
        Wed, 03 Sep 2025 02:54:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1756893265; cv=none;
        d=google.com; s=arc-20240605;
        b=PCXtYc4J7NNTiQO+Rj/auwwt1ZFvKXBE3WpmQFT7+YiSQ2+N8gm24nw/rv3BMHFcbB
         +wpzdiJIBkr7s2hhf5YNna3m7joUaCCSfro0a4YULcfGqZmNWwG47HQpu7/vIg3SOMjX
         9GAW6/q62ttzkbOaVTWGTJKzdwi9P1+Z8KQmOPvjM72cYvZNGwWRwdkesgso8umFEm4+
         MOABMvRMZQnQCR4RJ2Ao3wdqPP+tCIM/pElSts3gud6PhaWQ1Qs42ewPjco5rV6sdt9a
         oLNn5My9FGEQjY+/AXvPAN910/WHH6fXuj/TNeNDOT0ObIS7syrimpmynxtXpLkyPlsq
         8cuA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=n2Rzk7zMFMEV7RW/mx0yGAjSShG/CZFQjSUWSelah8c=;
        fh=egnqIkHu2IzG6ymEaeRdEoGd/w1j8i0n9k+eIuXyCMY=;
        b=O5Q8pgR9Smi4DZT+NPk1aCwRF5lICXKlJ1NgOSCBi5Ndl3b2aNtP9pQl0qWe7IduWs
         XvLVy6XchCdZIOH1d5Y0CkeUg9Ng/4Cjuke8HDWDaLnRob3B0KT0RjiOGyCQhKPPCCHN
         CcjgHDrNF9GEBSkzxDq7VNVJGWc+I0up1I4hRzgGRpzugLSM2dBuRUrSdMguzyy4brOg
         VIRAgsDr3ZbbRyXfOpuhWLWb+mdW4nVmTPAWW0V5FRwTbc6j9FBk/JiKG3IFx1ry7Goe
         EFeMcq2w16KoGCUtPj7CLElg3eN6BNsJrS3jJBTaRZqZNCW9lmYc1Y7il1dTWStgQFf+
         L3zg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=D72IoaHb;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-qv1-xf33.google.com (mail-qv1-xf33.google.com. [2607:f8b0:4864:20::f33])
        by gmr-mx.google.com with ESMTPS id 98e67ed59e1d1-329ca25750esi138655a91.0.2025.09.03.02.54.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 03 Sep 2025 02:54:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as permitted sender) client-ip=2607:f8b0:4864:20::f33;
Received: by mail-qv1-xf33.google.com with SMTP id 6a1803df08f44-726549f81a6so1962056d6.2
        for <kasan-dev@googlegroups.com>; Wed, 03 Sep 2025 02:54:25 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCW7JNHnwu0LDUkq8VrLWaMfbxVosD+Q6j+uaOWQ64R7lhe+FmjXJRuO0Keemy4ZJIX5mNK3zSP2bEw=@googlegroups.com
X-Gm-Gg: ASbGncuB2HJQBTPZzG3ZzJ0Q9g/86Ht55q8GUIL9yUEaTC4xzQEBwqUy8qeVJ1aDpV4
	gcCv+G/upylAE1fRjQAIL9PMmWszzWuHTYuHO66ec8e+ajzIIy7VVTdIE2voUza1sgNKGw6KzHL
	HjPxvPuUlBeuvxFxHMf0kHl0foS9hdxKgCt2A//sxWopsjbrOYOQBMp7fLr1EnYUCACiref/zfC
	NazXdhXz+ff9S8mMf/Hp5HOiIAQliFQ3sh4lNGfxQw=
X-Received: by 2002:ad4:5dc9:0:b0:70d:fee8:e588 with SMTP id
 6a1803df08f44-70fac870233mr189626166d6.34.1756893264049; Wed, 03 Sep 2025
 02:54:24 -0700 (PDT)
MIME-Version: 1.0
References: <20250901164212.460229-1-ethan.w.s.graham@gmail.com> <20250901164212.460229-4-ethan.w.s.graham@gmail.com>
In-Reply-To: <20250901164212.460229-4-ethan.w.s.graham@gmail.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 3 Sep 2025 11:53:46 +0200
X-Gm-Features: Ac12FXz83uIidiq7UvM7XG7YD3kWK8XfBqOv9db-g6kDKvYfHmTPpgNK10-2Ga0
Message-ID: <CAG_fn=UX9+1=CwGB-KCe+s85ZzQXfhqO+2dJVqs93XLKYedeWw@mail.gmail.com>
Subject: Re: [PATCH v2 RFC 3/7] kfuzztest: implement core module and input processing
To: Ethan Graham <ethan.w.s.graham@gmail.com>
Cc: ethangraham@google.com, andreyknvl@gmail.com, brendan.higgins@linux.dev, 
	davidgow@google.com, dvyukov@google.com, jannh@google.com, elver@google.com, 
	rmoar@google.com, shuah@kernel.org, tarasmadan@google.com, 
	kasan-dev@googlegroups.com, kunit-dev@googlegroups.com, 
	linux-kernel@vger.kernel.org, linux-mm@kvack.org, dhowells@redhat.com, 
	lukas@wunner.de, ignat@cloudflare.com, herbert@gondor.apana.org.au, 
	davem@davemloft.net, linux-crypto@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=D72IoaHb;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::f33 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Alexander Potapenko <glider@google.com>
Reply-To: Alexander Potapenko <glider@google.com>
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

> +/**
> + * struct kfuzztest_simple_fuzzer_state - Global state for the KFTF module.

s/KFTF/KFuzzTest


> +
> +               pr_info("KFuzzTest: registered target %s", targ->name);
> +       }
> +
> +       /* Taint the kernel after successfully creating the debugfs entries. */
> +       add_taint(TAINT_TEST, LOCKDEP_STILL_OK);

Maybe elaborate a little that we taint the kernel because these entry
points allow calling (almost) arbitrary kernel code upon user request?


> +       /* Patch pointers. */
> +       for (i = 0; i < rt->num_entries; i++) {
> +               re = rt->entries[i];
> +               src = regions->regions[re.region_id];
> +               ptr_location = (uintptr_t *)((char *)payload_start + src.offset + re.region_offset);
> +               if (re.value == KFUZZTEST_REGIONID_NULL)
> +                       *ptr_location = (uintptr_t)NULL;
> +               else if (re.value < regions->num_regions) {
> +                       dst = regions->regions[re.value];
> +                       *ptr_location = (uintptr_t)((char *)payload_start + dst.offset);
> +               } else
> +                       return -EINVAL;

There should be braces around this return statement, see
https://www.kernel.org/doc/html/latest/process/coding-style.html#placing-braces-and-spaces.

> +
> +static bool kfuzztest_input_is_valid(struct reloc_region_array *regions, struct reloc_table *rt, void *payload_start,
> +                                    void *payload_end)
> +{
> +       size_t payload_size = (char *)payload_end - (char *)payload_start;

You seem to be casting payload_start and payload_end to char* almost
everywhere, maybe declare them as [unsigned] char * instead?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CAG_fn%3DUX9%2B1%3DCwGB-KCe%2Bs85ZzQXfhqO%2B2dJVqs93XLKYedeWw%40mail.gmail.com.
