Return-Path: <kasan-dev+bncBCUJ7YGL3QFBBT7A623AMGQE2UUATVY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id 6D007970800
	for <lists+kasan-dev@lfdr.de>; Sun,  8 Sep 2024 16:10:25 +0200 (CEST)
Received: by mail-ot1-x339.google.com with SMTP id 46e09a7af769-710e93f6be4sf138630a34.1
        for <lists+kasan-dev@lfdr.de>; Sun, 08 Sep 2024 07:10:25 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1725804624; cv=pass;
        d=google.com; s=arc-20240605;
        b=IzSGe7IMFbNgJ0QztV4a3IfNcOeHop/Fk3b4DWOPUGy2JvxGu9FcxhtleZVuzA3IIQ
         gjAvGmIKAhU0+2TaXcVSpRk8AQ6NBkmD2+h/8268LfH2zf6hygOnhDGbR1Gj0lT9Pe7x
         EnZLjwdCT742Gv9Ckj2Y5HugoosGS4luVGN3V9yELNeV4ilFC5yX1e9m2HnfKv2TSEHY
         SJ5N+UKfySZJ7hcCPGmxugMe59orfjYv++E7HqtjDOR+VRG4HAc+z9sIr8YcIbBQO/B3
         Dqcfmn1ISY/5YPojBVbnNEqcSTsFUPjatnMCjFusw4NXi8SC7FuilpO2cD78IuGtoeLx
         A+4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=79YpLq6IZQrnCWInp9aLd45Tn0QJA3U3odnYd+cJb1U=;
        fh=aq9CBe0cynuL0QZ4C2k9NXrYdwbPvH3AKFxTN4mgq5U=;
        b=Sq4jaukLu5Gre+d6poIIVLj5XVlKE6hSdHamDF4LiFcheij5uvz9WiXyF9fUoYnQYd
         /0IC2LVYD5s0ISzsenMX4GRGTcbbHXWaU/4ii+JUIS7x91aMIRXv1yQnmFU20FQK1r5/
         T1+biSIPF209NiF+pLxz/uobdqgxI1WiK2Cit/4FZadd+jIqB0sAp8w9urZLEDYbjNw7
         hTWumDcWoAq3aqMhHR/hYUwB7idXdtXuHt8pbCFKQ7F+f1lw3GZwI9JZp8BYVr/7noOE
         3px/54Ap0RFuXVVkfdBJCOt6+jMa1SjPgfb5QU2GNwha3pr28rRInAWlYWHW9k3VZbux
         jEgw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=g21nXnFp;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1725804624; x=1726409424; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:from:date:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=79YpLq6IZQrnCWInp9aLd45Tn0QJA3U3odnYd+cJb1U=;
        b=HpTFg52pg2SC/DMFz48czoZh+21yMHIV0V86XDD5NunbNvb3ZJQ/0YXHQs08PncQjf
         49HOxE+wcclG3zmChKrmQRpQHXZ2oFbAgAdHQPmHh3RLjadkfjwR4nTOw1oLF2dwtCYP
         sQpgI8SUHNFg/GqsfVyE0m0Po3QGzZWzB0XOG1Ar08+JujqmDFq3oD/j6y2zojlbA8q2
         7GYI/N9655RtK2iQ+Hy5WbJKoYZ5e8SXNLXDgdEqZfCPbzEjmD7Am7UhpJN3vosmudu9
         Wmhm35hv6NRyVSeABKbii0Rk9g/zrd9i6VMgpoXH8LH5KfSrbganyFnHn3gow85G4l8k
         5pDw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1725804624; x=1726409424;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:from:date:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=79YpLq6IZQrnCWInp9aLd45Tn0QJA3U3odnYd+cJb1U=;
        b=AWuSCYpdTw+oqxo4rMS4eQg3LUSJ/IHQb+AJvBUPXDDkQfUyMhFCds8bHjVBQ+Zb9E
         px+6OwNqtrIMUjcPi/6RqNol3HXneAqTKGQOAWQptcOyAsF+D7aSZxYcvsQkBvWoj/VO
         6OHTQBtrjVpS4u2RHE8SZZcaBFCRfr5mVIZfEn51a/QbzpcL3YpWoRtuBHVjOdYe51Xx
         5qKL0Je6orY08ixaiOOyKGYcoYa/rm8NkMF1QzBstBToStcQV1K3qVROzbU+sc9eJJuG
         KA9w3YRGXckjiiJ5MwqajfyEQ/ME8X7Xj4Z/HyFdDQIuLQFDziwVHZY4NTRAqCOD2/IZ
         dqVw==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWg25RiWF/xNQB8d+dkU2Y5+Amsw7qOorVz+o4pFzC7A0097hUwpORO4lyM+GvpHwyBQQH3bQ==@lfdr.de
X-Gm-Message-State: AOJu0YwPA+Q1+JLuZCZiEn6XmqfEjlIUFXSIMyMmxeiP5tPjyI5H93lt
	H3F/53q9saQD212gbKIhHKJ+Doh6knPXTcNzmFRm91r0dSpg+Sls
X-Google-Smtp-Source: AGHT+IGIFmBXhqzYIzFVP80DOjALimAB46qjpz1rs4k3Eadcw4rU4iF6Oc1AAxvIlf2v2cXC0JGOOQ==
X-Received: by 2002:a05:6830:720a:b0:709:3d2f:7b48 with SMTP id 46e09a7af769-710cc25c955mr8966552a34.24.1725804623648;
        Sun, 08 Sep 2024 07:10:23 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:e885:0:b0:5e1:be65:204f with SMTP id 006d021491bc7-5e1be6524cbls906498eaf.0.-pod-prod-06-us;
 Sun, 08 Sep 2024 07:10:23 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWbNSYY5i4/C8on2U1zOJy6BG9i/JiswpYK8ihob1eD41Cu/63eMt7/FLiG2dvnypLnZ7yvLSRSYSg=@googlegroups.com
X-Received: by 2002:a4a:a8c1:0:b0:5e1:cabe:a3 with SMTP id 006d021491bc7-5e1cabe0a7bmr1470405eaf.0.1725804622984;
        Sun, 08 Sep 2024 07:10:22 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1725804622; cv=none;
        d=google.com; s=arc-20240605;
        b=aeV9ugMNf2EDf2+nz3Qb0uQzd5BF5tN9VA17IFjTTizRTLQdiLGPK6TbrzmapNkYuf
         Bm6bbQz/H4JdJa9/2glep6C5Ak7jGtcgw4AR1c1gzR95lxiUqLlAKgGwheXxPxZleuhG
         jwXOB5LqDtOBj/7micIfvxDgNIkiTButkqBy5moZoqIzYuPVl2H7V5/q76BOu5xhoh2C
         Ebag7qtQEMFBZlMzlE2Re716h/YLQAOBGN43HA+A0W13C7gr17n4sebfAZMywSjCRGkx
         BtRvscWZBfAz000fgoLm2gcUpO6O0rkmKu8Wdk6eUyDOHKxrw+dehwk2gwSsgsoYEG15
         LmPg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=WgSYlVkdJfDzLnzwfMIZMwocFWyW7ffAWfOXZRcWuw0=;
        fh=2dnXXZmOoQkzsDnOuqI6FPuSNQ3p86Y4/U7XFgJn5Zc=;
        b=IVa2h6Z9gOpAMQ5Btma+SxzTHZX9xIU6hDJjp5xIRgOgo/V8cCm1mMwla7uhDuki0j
         vuGxpahTWWucPu/I4NraQ2k98udpYTCbtAW9TFNLWPTpgkKNOaRI7eVHw5/vFG5n80+G
         kmicKsvXkItibKyEia1s688KoiTJ4zgAA5c3Pomlw2U8CYvC7SO/ivEmGe7uvVnxcALL
         heCWTf7jc5wESwA5E8LVAC9WRgdVZhwSQxIzkntyE8r9XsXIdjxBv1azyuJ3dmGuCS55
         x0DMFkr8BhxmKr7qSFJ7mZO6i4Ro/tBiG76roLDEpb8eq3cwRq/QIXH7+xJGJ3TdUy6E
         e95w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linuxfoundation.org header.s=korg header.b=g21nXnFp;
       spf=pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id 46e09a7af769-710d9e493bdsi103027a34.4.2024.09.08.07.10.22
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Sun, 08 Sep 2024 07:10:22 -0700 (PDT)
Received-SPF: pass (google.com: domain of gregkh@linuxfoundation.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id E96C25C06AE;
	Sun,  8 Sep 2024 14:10:18 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 66505C4CEC3;
	Sun,  8 Sep 2024 14:10:21 +0000 (UTC)
Date: Sun, 8 Sep 2024 16:10:19 +0200
From: Greg KH <gregkh@linuxfoundation.org>
To: WangYuli <wangyuli@uniontech.com>
Cc: stable@vger.kernel.org, sashal@kernel.org, alexghiti@rivosinc.com,
	palmer@rivosinc.com, paul.walmsley@sifive.com, palmer@dabbelt.com,
	aou@eecs.berkeley.edu, anup@brainfault.org,
	linux-riscv@lists.infradead.org, linux-kernel@vger.kernel.org,
	rdunlap@infradead.org, dvlachos@ics.forth.gr, bhe@redhat.com,
	samuel.holland@sifive.com, guoren@kernel.org, linux@armlinux.org.uk,
	linux-arm-kernel@lists.infradead.org, willy@infradead.org,
	akpm@linux-foundation.org, fengwei.yin@intel.com,
	prabhakar.mahadev-lad.rj@bp.renesas.com, conor.dooley@microchip.com,
	glider@google.com, elver@google.com, dvyukov@google.com,
	kasan-dev@googlegroups.com, ardb@kernel.org,
	linux-efi@vger.kernel.org, atishp@atishpatra.org,
	kvm@vger.kernel.org, kvm-riscv@lists.infradead.org,
	qiaozhe@iscas.ac.cn, ryan.roberts@arm.com, ryabinin.a.a@gmail.com,
	andreyknvl@gmail.com, vincenzo.frascino@arm.com,
	namcao@linutronix.de
Subject: Re: [PATCH 6.6 4/4] riscv: Use accessors to page table entries
 instead of direct dereference
Message-ID: <2024090808-elusive-deviate-3bbb@gregkh>
References: <20240906082254.435410-1-wangyuli@uniontech.com>
 <D68939319C9C81B0+20240906082254.435410-4-wangyuli@uniontech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <D68939319C9C81B0+20240906082254.435410-4-wangyuli@uniontech.com>
X-Original-Sender: gregkh@linuxfoundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linuxfoundation.org header.s=korg header.b=g21nXnFp;       spf=pass
 (google.com: domain of gregkh@linuxfoundation.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=gregkh@linuxfoundation.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=linuxfoundation.org
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

On Fri, Sep 06, 2024 at 04:22:39PM +0800, WangYuli wrote:
> From: Alexandre Ghiti <alexghiti@rivosinc.com>
> 
> [ Upstream commit edf955647269422e387732870d04fc15933a25ea ]
> 
> As very well explained in commit 20a004e7b017 ("arm64: mm: Use
> READ_ONCE/WRITE_ONCE when accessing page tables"), an architecture whose
> page table walker can modify the PTE in parallel must use
> READ_ONCE()/WRITE_ONCE() macro to avoid any compiler transformation.
> 
> So apply that to riscv which is such architecture.
> 
> Signed-off-by: Alexandre Ghiti <alexghiti@rivosinc.com>
> Acked-by: Anup Patel <anup@brainfault.org>
> Link: https://lore.kernel.org/r/20231213203001.179237-5-alexghiti@rivosinc.com
> Signed-off-by: Palmer Dabbelt <palmer@rivosinc.com>
> Signed-off-by: WangYuli <wangyuli@uniontech.com>
> ---

all now queued up, thanks.

greg k-h

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/2024090808-elusive-deviate-3bbb%40gregkh.
