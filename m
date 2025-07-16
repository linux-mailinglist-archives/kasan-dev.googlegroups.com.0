Return-Path: <kasan-dev+bncBDK7LR5URMGRBK6337BQMGQEHR4B7GI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x138.google.com (mail-lf1-x138.google.com [IPv6:2a00:1450:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 9889AB07CAE
	for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 20:21:33 +0200 (CEST)
Received: by mail-lf1-x138.google.com with SMTP id 2adb3069b0e04-553bc3e1d21sf95580e87.0
        for <lists+kasan-dev@lfdr.de>; Wed, 16 Jul 2025 11:21:33 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1752690093; cv=pass;
        d=google.com; s=arc-20240605;
        b=LwFke1m6oGbPkEbpMtg7djYxNqY5WWLiDGkExFice99T+JwsbNkcyJLCw3qEO44LBg
         rZvr3kdbMAxUU2vdV8iTtiTmZdNX3vtP9yCLDfhb7DcBFRwcCBpq2KAxSHuOydll0bhO
         n2ZFibV9Oolzpru1d5uQPdNn5h9UFqyWMwqAOiG+pqWqiHQz+4aYLWHx09y+GSpLv/iL
         Mzb3PI+i072Lp0NSiMwY8+HJ7DEcUaII4nOIFWfjOmE2zkMfyCKBm3IC1guFDgXjtM1h
         M0my9PT7o6zRLFNo7wV3HhkgXdyfe/I5+8F0aSAtIAhEVytkYgMZDKufXHZ89dBa4AP0
         ytiA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:in-reply-to:content-disposition
         :mime-version:references:message-id:subject:cc:to:date:from:sender
         :dkim-signature:dkim-signature;
        bh=XSIGiUyep7w4ReI3EDMrQq0lLdpOl7bQA1JgPsXU/oQ=;
        fh=zN0cp44Aa0InyKiEulFafNFyHBZxn8rFe4rB2TnYELA=;
        b=Y5Hm/InddaLf9/2eP3lbYRunmRhkfE7w98qNWwlzMkYlayr/bF3jZ6BPhQiaxaCpW6
         jjym0AVgtxq69vRcQKrQeBiPTjNpECs8S6XZgnbiyyEK5LmAc1yaLhdZg7YAzfY4dbrZ
         sgycJawgn3H6htSaPYVrG01gduqBl5lvxdVAGuQXb8wlgFK4H1GX+kKH6vdw9ThVlV5O
         5eW8TSHOef3QqXhe6bxmUmBzwPWS8Mqr1ddq/wgUGDR3d2Uvll9GlK1prnwmDah0r2BT
         F6bFrfGeDNXUMR0NHPWurNn8DPIPOOzFs+k9tJm2hV1XP0kgqq5Ai/VFr6t0023AGanB
         crDQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m+C711wi;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1752690093; x=1753294893; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XSIGiUyep7w4ReI3EDMrQq0lLdpOl7bQA1JgPsXU/oQ=;
        b=ktQ53Z8SuJUrlG08eoeniNRbdzPurWiYCzrae1Nc8PuCMoAxAfWp1erJ/qXGtm7/dB
         bEJQF1ov7johLedftFIYnjeXOkaeibIAnlVq/5XzH0hvcjOpDcSlxngXJYxEELmkvDEr
         Y0Hj2SGtAk8Ial+RxKSaVk2tW0czX7c0cHvds1A3kkRo7lHA7FlmdVJZGTqi7IYtYAZn
         sKqjZP+6fUacTY8Ny4PJTKTXl2xsEQsyBpwvkAbCgicHsHFrQacYLPMe6sjnUOuxujRo
         lzXTb5lauz/TZ87vXAqLwG+VJx3sfmmbO5thqSVoN5nYKYcEwG4dgqW0qX3pou/9GJ+A
         lLjA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1752690093; x=1753294893; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:in-reply-to:content-disposition:mime-version
         :references:message-id:subject:cc:to:date:from:from:to:cc:subject
         :date:message-id:reply-to;
        bh=XSIGiUyep7w4ReI3EDMrQq0lLdpOl7bQA1JgPsXU/oQ=;
        b=fwb6kP5DtHITHLIhC7WbPlFA/8py71LQFDF8Bq2XD/UkbMW2dfWhOSN5dqkt1tpBnp
         XGIXcR1LQffpxoWXMookPz2T9rI00vu2GoSV2/TEcrc3M8m7GK3vmORZ6byDwPxrHyaU
         tlIkR5eHH7lN9A/rPiaJrE7WPPfiRuGucnAVvN0QGuDw0kawdFYcxWN4JliHHc85Nk2y
         +J/ppkAaME7tCz11vbd67RLT84hFr6pBQNmPPBiA9Qv28d5+cZFBA1PBKzfAehLz65JF
         /Lor8EkTmXua+ZQZaYTDFZCK2tg1kNF5tI7MOg8lOz+sRAZRGSIW12q9zsi5zA1Ay5Ts
         Qf7g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1752690093; x=1753294893;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:in-reply-to
         :content-disposition:mime-version:references:message-id:subject:cc
         :to:date:from:x-beenthere:x-gm-message-state:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=XSIGiUyep7w4ReI3EDMrQq0lLdpOl7bQA1JgPsXU/oQ=;
        b=Wsv+1JQVv0SeU+ZRI0E7XcEkanC6JQXClUVgDwsRQso3zAGlnM1TE4RZ0lz9jyk3G/
         TpbHYNHSuLpPuCg/dj43jIqPYifTpBwIAWyyKYB1iOkMnLUTmwk0z1am1C5QKvAmLQBZ
         uE2rL7ISdS7A+vPHkVZwRwxg3JuOZazn2qam+EKpLa92Xsklgk4Vgq46iTR/OIxyDhoq
         jI1XgzxwqduVr3JlO/PQFMlgEGNEiW0RM11RyDnSfJLVtFc+WwssX+Fj4OEWz/osxEy0
         pjQUBMHuFboj1FXSxoaxBGwM4B64EQbD4bnG2fe9NrTdYW/XcbXePrGVS1BK38EQ/w2N
         XNOA==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVX9lUBDAhOx21si785qZX/whThLBCAcxf/xTAtxV5iWA9EjyOnI5ucj3BPk4J97XThNT35AA==@lfdr.de
X-Gm-Message-State: AOJu0YzRSdKQX/lRLmBkchCe79veC1HCfvxClQ75WKr7lx7uOl3zkWCu
	4XS8RgqWvlQ1YvXGq33W6phkh0ru3opcnB1Z4AXTmTHnGWz3OXqWkygE
X-Google-Smtp-Source: AGHT+IEXWjcyKD03+LkZnzgQx0msuAf945ahPSQdv2skN8jnmWs3Kq4oDcq1ptmA90sRnUkO/GmqYw==
X-Received: by 2002:a05:6512:3e1e:b0:553:d8ca:4fcb with SMTP id 2adb3069b0e04-55a23ef5b6dmr1012333e87.21.1752690092465;
        Wed, 16 Jul 2025 11:21:32 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZeMdCrHt+RcTpEJhsUh+AXxEwcA/U5IXvK9viIjXAh6WA==
Received: by 2002:a05:6512:23a9:b0:550:e048:74ff with SMTP id
 2adb3069b0e04-55a2878a4f3ls59268e87.0.-pod-prod-06-eu; Wed, 16 Jul 2025
 11:21:29 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVbqTzYlqR8efzDfbppaVzRKLXONdH8uwIl2QDW7eMGJ4v9ODcAlUJ+w3pdoz5PZiqqAU6ymXJImlQ=@googlegroups.com
X-Received: by 2002:a05:6512:132a:b0:54f:c6b0:4b67 with SMTP id 2adb3069b0e04-55a23edc9c1mr1345214e87.4.1752690089460;
        Wed, 16 Jul 2025 11:21:29 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1752690089; cv=none;
        d=google.com; s=arc-20240605;
        b=fh76O2dMxsuJ5/geRrUyrrjCQPTcCRqyOx/yFsWeAuvnpcMWDBNYuprGyyI0iWTRMK
         gTAZX3fElLsbS2gxD3KZBn3pZXgml5SFjGVHtG2+UO/c5X67PzNpydw+Hl4YaQFoxGP/
         GcqXS10kZQuu+G6Lf0dJkafVgiy2sDYTQButh5bewt44UsaWfBSYrwvpUGIEk020ivaL
         OiX01QYb9qXjKu/cqfBgAgFdrRpBSetCA3Ugq6F8pVI/szGalDwsW9jrkNAgPAx8ujBK
         3PyDn9iU76aF3uN3qN+o4KvWwZgfhhzkxN+cJF878iN5jC4JFt0BLzQi+3TZ/8wjhOV9
         jbrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=in-reply-to:content-disposition:mime-version:references:message-id
         :subject:cc:to:date:from:dkim-signature;
        bh=ZnrCFtIVZL8hyVV2JzefY+gIDN+ezQ0AtgNK2sjo+OQ=;
        fh=NFg83GfmZj3ZH715TOipYbnl83L+WI5Iy45A4Pe4oOs=;
        b=OkkhX7S75oLrn/4By3UkQA/WXwtHPuYgTdM8jy8QI1TXTOh5n2zi0784VCux+QY+lI
         MGeVIfssmGYN93UI0SVMb03GYEAlPNS5CRI0P9pQiBQrk/H3ENYDHXJ6khWNKQ+sMBCo
         4AkLZJBHarWJmTSqlcOkfl/Xaa0qxqsUnIpbuv0Jhu604MSxAUwkf0pRSVZy4nK7x2k+
         iL9RVqWvHBUF8srZpwjUtUUGhE2rP2D7u4fAF3pg0ZVbFvjhn5yjyhTcui9yv3F/9FJu
         vvrJKpLm9gbQ0wHxpckeaRn2UHgMKs5eHVF7aDNTc+XVJ0wjEURLhRFzqQLQ5SQ7zALE
         3miw==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=m+C711wi;
       spf=pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) smtp.mailfrom=urezki@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-lf1-x132.google.com (mail-lf1-x132.google.com. [2a00:1450:4864:20::132])
        by gmr-mx.google.com with ESMTPS id 2adb3069b0e04-5593c7e790fsi550509e87.1.2025.07.16.11.21.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 16 Jul 2025 11:21:29 -0700 (PDT)
Received-SPF: pass (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::132 as permitted sender) client-ip=2a00:1450:4864:20::132;
Received: by mail-lf1-x132.google.com with SMTP id 2adb3069b0e04-55502821bd2so189937e87.2
        for <kasan-dev@googlegroups.com>; Wed, 16 Jul 2025 11:21:29 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXgq6sM+wrz3PMzzcmuoArmZ75B9L3WKLBcYW34Aj7R/y6DCeon7SSlMG0Xojx8HePEgSqyF9G9Q30=@googlegroups.com
X-Gm-Gg: ASbGnctMEwpmqOgQevX8nrrkU7KTfZgfztMFX88KXZ1niKI6NNFakJJZuXF3Bq+BCDx
	so1bgpqJJGfDa/sfh07f5qMLqNf+CEMJlx7g6/ceML9WjYsSnWF4WQmflP7Vg6NYXeiQRyabvet
	MP7pBnHuN6RpTnqUN1b/2HfR+KNi+sB4iBre6DFkpraze6V0yF/erXS/ofLP6PWo3k5D9z63cqZ
	na4/1B11s/KniQstUMPOYtamGo+/ZBJ3RxcCE7bPQwgH6B2FrRhmU6U2+FWyg+QbmW+EFCueXi+
	Yb55MJ9zSxNzGL//2YPq2SAv1iHEmw1WOaJGEFscJtihoSeOYVpj5cdc78rk6S893grDNwu6R1+
	GVPoNjHsmcLjQt1cvpvyRBh1ekSzu90qtcgidZKBqXIWoVb9xAjurQ3o0OQ==
X-Received: by 2002:a05:6512:61a1:b0:553:314e:81f7 with SMTP id 2adb3069b0e04-55a23ef4e8amr1113594e87.17.1752690088553;
        Wed, 16 Jul 2025 11:21:28 -0700 (PDT)
Received: from pc636 (host-95-203-27-91.mobileonline.telia.com. [95.203.27.91])
        by smtp.gmail.com with ESMTPSA id 2adb3069b0e04-55943b6bb54sm2743150e87.179.2025.07.16.11.21.27
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 16 Jul 2025 11:21:27 -0700 (PDT)
From: Uladzislau Rezki <urezki@gmail.com>
Date: Wed, 16 Jul 2025 20:21:25 +0200
To: Marco Elver <elver@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>,
	Alexander Potapenko <glider@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Ryabinin <ryabinin.a.a@gmail.com>,
	Andrey Konovalov <andreyknvl@gmail.com>,
	Vincenzo Frascino <vincenzo.frascino@arm.com>,
	kasan-dev@googlegroups.com, linux-mm@kvack.org,
	linux-kernel@vger.kernel.org, Uladzislau Rezki <urezki@gmail.com>,
	Sebastian Andrzej Siewior <bigeasy@linutronix.de>,
	Yeoreum Yun <yeoreum.yun@arm.com>, Yunseong Kim <ysk@kzalloc.com>,
	stable@vger.kernel.org
Subject: Re: [PATCH] kasan: use vmalloc_dump_obj() for vmalloc error reports
Message-ID: <aHftpSnSit__laMx@pc636>
References: <20250716152448.3877201-1-elver@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
In-Reply-To: <20250716152448.3877201-1-elver@google.com>
X-Original-Sender: Urezki@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=m+C711wi;       spf=pass
 (google.com: domain of urezki@gmail.com designates 2a00:1450:4864:20::132 as
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

On Wed, Jul 16, 2025 at 05:23:28PM +0200, Marco Elver wrote:
> Since 6ee9b3d84775 ("kasan: remove kasan_find_vm_area() to prevent
> possible deadlock"), more detailed info about the vmalloc mapping and
> the origin was dropped due to potential deadlocks.
> 
> While fixing the deadlock is necessary, that patch was too quick in
> killing an otherwise useful feature, and did no due-diligence in
> understanding if an alternative option is available.
> 
> Restore printing more helpful vmalloc allocation info in KASAN reports
> with the help of vmalloc_dump_obj(). Example report:
> 
> | BUG: KASAN: vmalloc-out-of-bounds in vmalloc_oob+0x4c9/0x610
> | Read of size 1 at addr ffffc900002fd7f3 by task kunit_try_catch/493
> |
> | CPU: [...]
> | Call Trace:
> |  <TASK>
> |  dump_stack_lvl+0xa8/0xf0
> |  print_report+0x17e/0x810
> |  kasan_report+0x155/0x190
> |  vmalloc_oob+0x4c9/0x610
> |  [...]
> |
> | The buggy address belongs to a 1-page vmalloc region starting at 0xffffc900002fd000 allocated at vmalloc_oob+0x36/0x610
> | The buggy address belongs to the physical page:
> | page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x126364
> | flags: 0x200000000000000(node=0|zone=2)
> | raw: 0200000000000000 0000000000000000 dead000000000122 0000000000000000
> | raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000
> | page dumped because: kasan: bad access detected
> |
> | [..]
> 
> Fixes: 6ee9b3d84775 ("kasan: remove kasan_find_vm_area() to prevent possible deadlock")
> Suggested-by: Uladzislau Rezki <urezki@gmail.com>
> Cc: Alexander Potapenko <glider@google.com>
> Cc: Andrey Konovalov <andreyknvl@gmail.com>
> Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>
> Cc: Sebastian Andrzej Siewior <bigeasy@linutronix.de>
> Cc: Yeoreum Yun <yeoreum.yun@arm.com>
> Cc: Yunseong Kim <ysk@kzalloc.com>
> Cc: <stable@vger.kernel.org>
> Signed-off-by: Marco Elver <elver@google.com>
> ---
>  mm/kasan/report.c | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
> 
> diff --git a/mm/kasan/report.c b/mm/kasan/report.c
> index b0877035491f..62c01b4527eb 100644
> --- a/mm/kasan/report.c
> +++ b/mm/kasan/report.c
> @@ -399,7 +399,9 @@ static void print_address_description(void *addr, u8 tag,
>  	}
>  
>  	if (is_vmalloc_addr(addr)) {
> -		pr_err("The buggy address %px belongs to a vmalloc virtual mapping\n", addr);
> +		pr_err("The buggy address belongs to a");
> +		if (!vmalloc_dump_obj(addr))
> +			pr_cont(" vmalloc virtual mapping\n");
>  		page = vmalloc_to_page(addr);
>  	}
>  
> -- 
> 2.50.0.727.gbf7dc18ff4-goog
> 
Acked-by: Uladzislau Rezki (Sony) <urezki@gmail.com>

--
Uladzislau Rezki

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/aHftpSnSit__laMx%40pc636.
