Return-Path: <kasan-dev+bncBDK7LR5URMGRBAPN7S6QMGQEEGRBIEI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id C2BBDA46532
	for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 16:43:04 +0100 (CET)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-4399a5afc72sf35283815e9.3
        for <lists+kasan-dev@lfdr.de>; Wed, 26 Feb 2025 07:43:04 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1740584578; cv=pass;
        d=google.com; s=arc-20240605;
        b=JqN/6fjdp+NrsJKnPpyb8uDCAIU5ltyffkATvIIQlq73s3brvV1FmomPA9fggMjkPB
         VjfUudNx6VTcS7VpFBUhkSlpyTPIJqzg9EgmDmWz4YzFmbsh+Vm8ILxb5ED3yvtM8tiw
         MLGhoOfi5r6IacasKBwdEYBf4JTAf0guZjoxIszzfPJClduNpkDhxTQg75GOPyaS/llB
         Wye6u56Hrm+yA5upE0wXkIMXi/u8rzMji0OqP+3CzXNGYl/oj75quu0ay+HKZc9OOM4S
         16/AL73oacCimwOHJEo+FxkfmZWxLEI1Ky929NnephOu10mz3USREyPEQrjGrpkNSTTS
         it3w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=vwGwp91Rk6vJxBazoIaoc08HiaQnGgMo/XXYgkazpKQ=;
        fh=2OWI7nE/3ScHz40zCPgUR4lE5p2d1z4FqFNU9Ps8EBI=;
        b=XT52pdG507R5H0TUUnhJs0QwCIt23n5G8kqjrEeWTqKL8NnqYyjttAl6GAlykiHDln
         Pny/NIZaSFBrVeFfiXK8x+ih//dDA9/P3dhhvJxdtDfP2J9KDtv9tUkq3aEtJZu0jcLQ
         HQZmb6SoWih8U6uiyXwuLY5Xt3Ei++RuqN7arw4eBd5EbHn1boEt2jopE5qZaSsEEv1j
         Okx37ERlopDWq2/59GZNidAC2VEyqxhsEDiE7dO/DUSZsZGY3msHX/XEGj2Mla6ie98b
         Gb8Cc0M0rInErqX06OXwIpFh286qLTV7WEOd4UJZrmnbrWp4AHFipZT8vZ1aAB895G+0
         UDhQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Hby2uaY/";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1740584578; x=1741189378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vwGwp91Rk6vJxBazoIaoc08HiaQnGgMo/XXYgkazpKQ=;
        b=jqmrE7Ftw56CloV7D9y+Q31DUkAF3zP5j/XsgyfAjp30meJN7WERGztuva7t2Ux8dB
         XzwHB5wkAzfO0nSmRoJvhv8PVViVfF3NPpaHfk5KK1dIBbQZFQQyB19zFXIi2yB8W9mm
         zh19i73eb+6hbBAImZseY6X/Z3vwkLlBdZ/3cxxoYdebOWQjXYzSDOnZLLoQ4ADxlebO
         XZzIQlXJ5Cn1JcSgnoDpE2eW005AMylljcsU5MFX06cPyF/hrfPy/Cv+dM9Eko5ESlCG
         fH7aJ8oG+Sr/F6VYGgcPF7uDEiTHfvTGZQgNnqVNDNH9omMsRDxnr1VVsiQhnMTmPF8A
         WAow==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1740584578; x=1741189378; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=vwGwp91Rk6vJxBazoIaoc08HiaQnGgMo/XXYgkazpKQ=;
        b=YRJeoKYBYCTgcGYUMOhA6wJrdxZ6fnSG61Op8KjOtj49xjMrvJXFTAUqathvTAdneH
         H0bSflw9eMxRAacvzVEsgPICOogpp9WXh3QH+UCTyryKoB/77IjMx0hWmI3BGwPTYAdE
         JAEBGLA9ElzCSvHuAUSncWs237GTn5cPT70dp6ePowD88GXqWs2xSCZpWnqlj0Oq19PV
         KbfY3c5sM8y9idovWehiyD+nXm0vUx+Ew6V7i8q2vuWlOcFyKT3pDc15FTE0xfn6+h0V
         J1MH9vj6kYDDDWdAvi3ZozscJnhSJ7bfRU912DjoVlgQbln5i6Gc7XnkCq5bbvHtcbZl
         UrXg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1740584578; x=1741189378;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=vwGwp91Rk6vJxBazoIaoc08HiaQnGgMo/XXYgkazpKQ=;
        b=B0Bg+/iy+iU+33JzOD0K7e2t9n6LdsQsW5vAJ8GVX7PhNzoL90D8b3pZRVQ3CIoyPX
         +KTuBK08tFlwm9oB8GVYq554fMCSHMnsCnj/++STemJDb0AIue7CIDzVR8TvmzUN+UhL
         EklbTBGtHvg7h88NK27LY0Tclv33VZyIvAWcD5D6i7su3+e81NPEN0WwKy8v9RgEOvPe
         ioxZsWIZX0weuZ/AbfdWNBOYOJ2nCy5hk1botWe0U0WAtP462mVM+l1pzjjC4xR7FVvN
         S1s13wdxrWpJlcsT+Cuk8Spgv8BITQVOZTdgHi3CexM6nCd4Eqoh9WozJoRbnFpWlQJp
         FDsw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVvtgaGlmpZGFkmXb/9HOG9aQzfEFz1lsBCN7QYX3rLZEZ64E3mP+8Gmodzdo31EyxpTSf//Q==@lfdr.de
X-Gm-Message-State: AOJu0YzQ/22xUitB+bT2dU4edqrV/e95Q+vb7N2mh1UICH/5TIFMCAPw
	NLap72vmzrPULhoGm5Noh+MNqMoACUxbRZq/zTjlBeGKebOXCvLE
X-Google-Smtp-Source: AGHT+IHOMUERO8j33fESC2dyXs20ktmJ3KZdwSOEOSaMhK8LiCv7Wjgae6sBXOVLA2u5bjV2egIaYw==
X-Received: by 2002:a05:600c:5106:b0:439:a25a:1686 with SMTP id 5b1f17b1804b1-439aebda0bbmr159691015e9.25.1740584577998;
        Wed, 26 Feb 2025 07:42:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com; h=Adn5yVFcQmqB/lJNR4mksFLWZqXBu4kjtfzMEEPHh4k1JyeFXw==
Received: by 2002:a05:600c:42c1:b0:439:8930:857a with SMTP id
 5b1f17b1804b1-439ae29b75fls5479215e9.0.-pod-prod-03-eu; Wed, 26 Feb 2025
 07:42:56 -0800 (PST)
X-Forwarded-Encrypted: i=2; AJvYcCVCbSWGFjG9EpORt9LKEzvUghergvbMt3jSjPXjwpRtlDtFh1xza90NDApwUkMwHVqjCpvCezzedRg=@googlegroups.com
X-Received: by 2002:a05:600c:4683:b0:439:8523:36cc with SMTP id 5b1f17b1804b1-43ab07ab212mr87041595e9.11.1740584575842;
        Wed, 26 Feb 2025 07:42:55 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1740584575; cv=none;
        d=google.com; s=arc-20240605;
        b=G9Embw14ZIMC22njQowLBV3zCbzcxR9y6izouZzftJTYWQMfehHYhDyYO9wlzmex1g
         kfb1dGcB/N1EmKIBLv2nx6w/SgbWuY7/Rte1IOVkr+pGheeXA1QJE8UFrf6E64AAZU2h
         YLyEkjEURtwH7UOKJkEzajDQfKLWJFJ32ivLCtd3JWpTa0D+eTjCu6w1fUBkEFk14Is6
         Pc6ElRSrJtyrOqawrYk4vYJhGZ7r90A3OisHRxIkAiU5/2Mj1YpMWYBApMWbBQw78WPo
         iCLqnlgvHnDQLUMSJKhr1E6jh0QltMpvR3fzr0ggr93Tzca4uYe3RoZ1vFWk8z/mUCX8
         E83g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=EC1eEy16dWk77oUwR2C/pnSf364aeM1Gi+/TEG7RfzQ=;
        fh=IQZEsYZJ3idFk/7+9LjM0s5Dc91CbXE1jqINDgzZKhs=;
        b=Fc6gld6K8i9DTSH0mgyQBVIY30yi+H7fuI7YHH5aYrPFIY4LFA4Oykh1KoXBRFcgKT
         ibFTpCGg++GDwAjZgYe09joVD+XKqpgLmF9GSoYvJyYxo33CVtoc6KkHljilSjTvgM8d
         bB17oSCF1pLxVuqKRJ797Hkj4tt/2FcZuzZF2xEnxq3sV3fwtfEz3FpqghXT3TKev+C2
         eD5nTUm56YZ+fpo2F2ReZx6hECcgZ1heU0SpMcFgEwh1iXY6qcLE2xUHWzDCJVjx97ml
         nWoHhZYd8jvkIRNxMM/C+R1qVJaz32xKzEc+h0+2y2SH4zRHejUy62Xn/0+wOZ8LXHII
         i/Xg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b="Hby2uaY/";
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lj1-x233.google.com (mail-lj1-x233.google.com. [2a00:1450:4864:20::233])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-43ab3742b77si4005245e9.1.2025.02.26.07.42.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 26 Feb 2025 07:42:55 -0800 (PST)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as permitted sender) client-ip=2a00:1450:4864:20::233;
Received: by mail-lj1-x233.google.com with SMTP id 38308e7fff4ca-3061513d353so73663781fa.2
        for <kasan-dev@googlegroups.com>; Wed, 26 Feb 2025 07:42:55 -0800 (PST)
X-Forwarded-Encrypted: i=1; AJvYcCX5JhMKkLO0j+qn/PSkNPWXS1+KHvF6z9qUVzdxOB32gC9dizNoTFWYUSloYq39DMWmyFuEV7eW2Gk=@googlegroups.com
X-Gm-Gg: ASbGnctLgJSukPM5gZSyQPW3YvYV8/+7/OQF53hOeoENkc5ehYhp1M3NsrCR56bhZ+S
	3kURdg0ZmVDVwLurjEquzsPAEeXL52b12foVs0khdPXdgZdGHsWPPDKk7AyBPhNfptyiAculaLS
	itb39YKveTcRD8zleKRdWAzHDszVjoO0R/SejdPcUvBrgbGKSBkFf4OmE8fwJRFTBZbVCzGIQvQ
	YgIHpQkE8S6ZM6Lx7ydp1j2Mv2KoNQd2w9feBaQTBLwrQRoEDKShhn7OzLon15mupGNqPzW5I4w
	baLCAlbAZVwt2gA/FVXJLR708S2bqBMj74adYsSkbmwf2lvc
X-Received: by 2002:a2e:3207:0:b0:309:bc3:3b01 with SMTP id 38308e7fff4ca-30a5af4c7bbmr85358301fa.0.1740584574916;
        Wed, 26 Feb 2025 07:42:54 -0800 (PST)
Received: from pc636 (host-95-203-6-24.mobileonline.telia.com. [95.203.6.24])
        by smtp.gmail.com with ESMTPSA id 38308e7fff4ca-30a819ebe39sm5640871fa.28.2025.02.26.07.42.52
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 26 Feb 2025 07:42:54 -0800 (PST)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 26 Feb 2025 16:42:50 +0100
To: Vlastimil Babka <vbabka@suse.cz>
Cc: Uladzislau Rezki <urezki@gmail.com>,
	Keith Busch <keith.busch@gmail.com>,
	"Paul E. McKenney" <paulmck@kernel.org>,
	Joel Fernandes <joel@joelfernandes.org>,
	Josh Triplett <josh@joshtriplett.org>,
	Boqun Feng <boqun.feng@gmail.com>, Christoph Lameter <cl@linux.com>,
	David Rientjes <rientjes@google.com>,
	Steven Rostedt <rostedt@goodmis.org>,
	Mathieu Desnoyers <mathieu.desnoyers@efficios.com>,
	Lai Jiangshan <jiangshanlai@gmail.com>,
	Zqiang <qiang.zhang1211@gmail.com>,
	Julia Lawall <Julia.Lawall@inria.fr>,
	Jakub Kicinski <kuba@kernel.org>,
	"Jason A. Donenfeld" <Jason@zx2c4.com>,
	Andrew Morton <akpm@linux-foundation.org>,
	Roman Gushchin <roman.gushchin@linux.dev>,
	Hyeonggon Yoo <42.hyeyoo@gmail.com>, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, rcu@vger.kernel.org,
	Alexander Potapenko <glider@google.com>,
	Marco Elver <elver@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	kasan-dev@googlegroups.com, Jann Horn <jannh@google.com>,
	Mateusz Guzik <mjguzik@gmail.com>, linux-nvme@lists.infradead.org,
	leitao@debian.org
Subject: Re: [PATCH v2 6/7] mm, slab: call kvfree_rcu_barrier() from
 kmem_cache_destroy()
Message-ID: <Z782eoh-d48KXhTn@pc636>
References: <2811463a-751f-4443-9125-02628dc315d9@suse.cz>
 <Z7xbrnP8kTQKYO6T@pc636>
 <ef97428b-f6e7-481e-b47e-375cc76653ad@suse.cz>
 <Z73p2lRwKagaoUnP@kbusch-mbp>
 <CAOSXXT6-oWjKPV1hzXa5Ra4SPQg0L_FvxCPM0Sh0Yk6X90h0Sw@mail.gmail.com>
 <Z74Av6tlSOqcfb-q@pc636>
 <Z74KHyGGMzkhx5f-@pc636>
 <8d7aabb2-2836-4c09-9fc7-8bde271e7f23@suse.cz>
 <Z78lpfLFvNxjoTNf@pc636>
 <93f03922-3d3a-4204-89c1-90ea4e1fc217@suse.cz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <93f03922-3d3a-4204-89c1-90ea4e1fc217@suse.cz>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b="Hby2uaY/";       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::233 as
 permitted sender) smtp.mailfrom=urezki@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com;       dara=pass header.i=@googlegroups.com
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

On Wed, Feb 26, 2025 at 03:36:39PM +0100, Vlastimil Babka wrote:
> On 2/26/25 3:31 PM, Uladzislau Rezki wrote:
> > On Wed, Feb 26, 2025 at 11:59:53AM +0100, Vlastimil Babka wrote:
> >> On 2/25/25 7:21 PM, Uladzislau Rezki wrote:
> >>>>
> >>> WQ_MEM_RECLAIM-patch fixes this for me:
> >>
> >> Sounds good, can you send a formal patch then?
> >>
> > Do you mean both? Test case and fix? I can :)
> 
> Sure, but only the fix is for stable. Thanks!
> 
It is taken by Gregg if there is a Fixes tag in the commit.
What do you mean: the fix is for stable? The current Linus
tree is not suffering from this?

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/Z782eoh-d48KXhTn%40pc636.
