Return-Path: <kasan-dev+bncBC7OBJGL2MHBBSUL53AAMGQEFIFUCBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb37.google.com (mail-yb1-xb37.google.com [IPv6:2607:f8b0:4864:20::b37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4F34AAAE613
	for <lists+kasan-dev@lfdr.de>; Wed,  7 May 2025 18:09:48 +0200 (CEST)
Received: by mail-yb1-xb37.google.com with SMTP id 3f1490d57ef6-e77d3eeed04sf53435276.3
        for <lists+kasan-dev@lfdr.de>; Wed, 07 May 2025 09:09:48 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1746634187; cv=pass;
        d=google.com; s=arc-20240605;
        b=Dwvy4iiua8F6CCDofU0nNYR13aC/dykz4z2j6SLOR7BoUrXguNkrdpTua+VlMbCfqf
         GwVBGptH6t62T7qm4y+SeC9ey4X3m9nq98X5EHmP3XIosYl+rLjSYkmwcT3GVOSlrL8p
         zsdi1zbrTK4i+wAzS7z0Pct4vjy5dTQE9hxmovxSWFXdolG7uWkIon6xEtweF5MlIt15
         DwDFH7bxDM1eNfBXT8MVxK6kGk+7/HPPC5JXsdend9uxfjXoajG79RvgLpDB1UoTJ+9A
         OXV53YjbCDPSVEe99nPwodYw0wGa9YFVmgFwm6QWKKR/KuxueIupPG3yJ4S7A6Vf7OeZ
         +9Iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=CDb2qcVNB06BjVS8jIfGvay05rS0zwYJ3A1E8QzF91Q=;
        fh=xRF/dF5VyGreErsaZ4N644aawO7LJcA6nAl7wwqi0xI=;
        b=DW8ik8oXSKF/LMG/6u2FiZC6j7XgS4L0TWqZQPznwujSEW8VgkgPk9XeCwMOTDy6OX
         6KOYYtFndTWPda4aM6GgrFmsopmdabvvBa3T25+0GYzn406TMsJxn7HzJ0zbugQqiPLS
         aofRGEowBNGeRzUxkgYhQ+E7B6a9sB5LEmFA4cwOdSMVA5noKA9i6V64WPiYBOfvHn3P
         V0A/0lpOXV2j4T3cYVmJvc9vsFfyejMCBxAmb8e94zRNGj9My0JZZqZ1LW8wYaO2w2rl
         pPr0GYEG/NhSEZISgOrIpNDfziPFm1DF3hx21Bx4DpPbY/DcISTbB3O24ql7jnVSYcmY
         KNJg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p27FpW44;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1746634187; x=1747238987; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=CDb2qcVNB06BjVS8jIfGvay05rS0zwYJ3A1E8QzF91Q=;
        b=DKZftuIdZfkgb3BSNd7YRl2JwSkL5O8Vxsj/aNnBoMT12G7gkOLifauCiJiqa5a9m/
         XSFJrk2kxdk/yP7x7al7IVtp4pbeMIi2CnkvtOpA2jgu4FFoSVQLULhFZrDSYeDrq5oY
         gmDkepKDMfSCWhrIsPKx8utxF/5GZGY3SUQpHSiv1asdCnNEP71rQswdMZyGlopzJLtQ
         IuIwhsm0bN8miFYbJpUV5mtt1zvqV1cZHInMVySd72zvezDNQMoH5+wmR0T0LQat7Ixl
         85XjO/Dllhj3eS9pC2KZGAX5Z5sJlME7tPoD0p38D16sZekYXgdg6ktPg6pFWP5N98CH
         Eejg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1746634187; x=1747238987;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=CDb2qcVNB06BjVS8jIfGvay05rS0zwYJ3A1E8QzF91Q=;
        b=jR9X3fzaKNn2NUrzuYmxFV8tlVjW2F5p88H9+VgGam55X1s0itG74Z8XElOKxgMzxW
         q9B3N7vy2PaZMmsaY1RNXIh4MCFsKMvqEL74vwOGNo3OwgBYE8oS2vn2zTXTnnHscgHQ
         Cp9F8lCLBpLCjqlBK+TWaecW9A2YtRnpRRe586k7DN6z6f0hljSMObzYIgvK2IDFw5Ot
         jpLzJI3CaUhHqNeyAafH05ESVfuXdVYpXoIHKW0zXMmMLL69+s6KNUmTal7tWhtvhDql
         qwZhJJIK+nHO70O3xEtQI2cBbsOIxZBuisj9oqU37ZJM2DAcTr1zvbPYfI8veRMZRe7w
         N3xw==
X-Forwarded-Encrypted: i=2; AJvYcCU4MwMLl08sovAbyQ8Qn4vDHr7zOvKCFqk5ePX/H4/7MQ8Eu0uSvIFl+A3goPa2gjdgeW2X0w==@lfdr.de
X-Gm-Message-State: AOJu0Yz6imxWGPy4b4oNHayFumlCkex+rqROp3DE8y7+g5XhubNM1ND+
	7iJguer5TilRyCeUDL9ELuhCKaQIL4+ff7qIMekN3IXLOR7KxIpw
X-Google-Smtp-Source: AGHT+IFYWvgIcGX8+f/q5fZyxjiD8X5OJLzeAPSvmGPhZ0dCdaeKEd0LC6n1K8pYRtXCXUlvDPGlgw==
X-Received: by 2002:a05:6902:218d:b0:e72:febb:48ab with SMTP id 3f1490d57ef6-e7881c178a2mr4571139276.45.1746634186969;
        Wed, 07 May 2025 09:09:46 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AVT/gBHRTHDtdoYGJzrci1pzev06sWE5sUlwGU2buSUdLPmHtg==
Received: by 2002:a25:3c84:0:b0:e75:60d4:326c with SMTP id 3f1490d57ef6-e78edfd675cls33588276.1.-pod-prod-06-us;
 Wed, 07 May 2025 09:09:46 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCX2Q9IWFanQC1yP6POxNEPhze+R2zDxd4m/DTIpwggYIMoAoOIZ+TQVrqWJt8gd2ty6yxWQ/zGHlHM=@googlegroups.com
X-Received: by 2002:a05:690c:4881:b0:6f9:525d:a096 with SMTP id 00721157ae682-70a1d9d7b30mr57007897b3.3.1746634185852;
        Wed, 07 May 2025 09:09:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1746634185; cv=none;
        d=google.com; s=arc-20240605;
        b=TjwLEhBEoU2sDbBnQBRm38AY+kqJI3uSDEUZTsN0qKPRpwBJFpF4+IJtNa4OA1GlQo
         O32X2G7F2yvKfOFPNzRFvN5oZofXA1cEa2MpgjfM/XSzpkzPOZdDE4jDh2v/PsZkij4m
         /qkYdZNfpRyZMCy9W4g9dOHRTuFrqWvBIUffhwcmTUARjo83ekZLfhri0kcjzKTnQ52/
         g03QWzoDdd4Vv9GLodKIwEYLiQybYc5uTBvu+cWdVAncSfqljojb3UI0ennf6UqQxEPJ
         s6h88WZOJdzE9AKMUKKCGYqdK0Pdj4xhHACtJVekhJm24nDwhacAP/uYDO9uG2Knp1Lh
         I76g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=kLejrPG7PIJ7PYQPHe6WOHWJ36xN91BpiH0KdWoRz34=;
        fh=zpa7E2KXQJqu6AqLpW/o46ILGuvC9ovmIsba/pGy+CA=;
        b=fs0d+PU9Yzmg5B1kjvB60ZsZ2r9eSsFhJpbqxzBEud4n03zASFAPuGyOBLEBxbGomV
         X8iHZxVRWhsMEX8kR6TiTW0xiVb+aiZY8K/KJba6GYJLRB4iyB3u2NOXYKioDsM+vl1B
         ebYOb6UijOrO6A9VVzX18VZrZglCNb3eg4q7aUsjRwxTegM2ZMWseWZ39WqCGNqSFDAz
         Hs3+Oj+5X9zGLR1c6HhvB/jeRnwmSTjBBOYLJSrMCPTdNB9BJXY04pGfx+xataXbBOTe
         WZm5v5k02CobN67cVuaRMXrRD9BeJbwRpk2VuJTBnZAKBUmyle89D0irzjrL19UmdYPy
         g2TA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=p27FpW44;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-pg1-x52e.google.com (mail-pg1-x52e.google.com. [2607:f8b0:4864:20::52e])
        by gmr-mx.google.com with ESMTPS id 00721157ae682-708c38eff54si4491267b3.0.2025.05.07.09.09.45
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 07 May 2025 09:09:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as permitted sender) client-ip=2607:f8b0:4864:20::52e;
Received: by mail-pg1-x52e.google.com with SMTP id 41be03b00d2f7-7fd35b301bdso8617529a12.2
        for <kasan-dev@googlegroups.com>; Wed, 07 May 2025 09:09:45 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXii4YLLzgT/KCFGuUi3u9Ne+FuuPFkWG2rUxD+3HScyShfJNEo5bTBe2WBGl7v4NtAkcB4rp/FJgc=@googlegroups.com
X-Gm-Gg: ASbGncuP7hgcK7cSob4DJsuTq9OiceFjVc326yb8iwFTFSH674YbxjjaFk5Lk6DThKn
	prd1HXdTYQhpswoZOsppbZZp4YS+OxUn8ubphhlTM7ltHuZrv+6RxdAA7oafgkhzd9RIAN2n+De
	Wc1M3LtflcUlZ2RiFU/RVh8OW8a2QxkqbJfTbmmbnqp8NmeiZ0ow+dOrdbsLAUfZ7q
X-Received: by 2002:a17:90b:1d82:b0:30a:4d18:c71b with SMTP id
 98e67ed59e1d1-30aac1adf44mr5603903a91.20.1746634184658; Wed, 07 May 2025
 09:09:44 -0700 (PDT)
MIME-Version: 1.0
References: <20250507160012.3311104-1-glider@google.com> <20250507160012.3311104-2-glider@google.com>
In-Reply-To: <20250507160012.3311104-2-glider@google.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 7 May 2025 18:09:08 +0200
X-Gm-Features: ATxdqUEUF2xw2fcMp5Sns9UdG5E_bP8PREEb_uX1l1rQb7kTDEN8klIAHon6RUU
Message-ID: <CANpmjNMUFmnVweY5zCkkszD39bhT3+eKk1-Qqc0LZTUdPN0x=Q@mail.gmail.com>
Subject: Re: [PATCH 2/5] kmsan: fix usage of kmsan_enter_runtime() in kmsan_vmap_pages_range_noflush()
To: Alexander Potapenko <glider@google.com>
Cc: dvyukov@google.com, bvanassche@acm.org, kent.overstreet@linux.dev, 
	iii@linux.ibm.com, akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	kasan-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=p27FpW44;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::52e as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com;       dara=pass header.i=@googlegroups.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Wed, 7 May 2025 at 18:00, Alexander Potapenko <glider@google.com> wrote:
>
> Only enter the runtime to call __vmap_pages_range_noflush(), so that error
> handling does not skip kmsan_leave_runtime().
>
> This bug was spotted by CONFIG_WARN_CAPABILITY_ANALYSIS=y

Might be worth pointing out this is not yet upstream:
https://lore.kernel.org/all/20250304092417.2873893-1-elver@google.com/

Also, for future reference, feel free to dump the diff here that added
the annotations that helped you find the missing kmsan*runtime()
calls. I'm sure it'd be of interest to others. At one point we may
upstream those annotations, too, but we'll need Capability Analysis
upstream first (which is blocked by some Clang improvements that were
requested).

> Cc: Marco Elver <elver@google.com>
> Cc: Bart Van Assche <bvanassche@acm.org>
> Cc: Kent Overstreet <kent.overstreet@linux.dev>
> Signed-off-by: Alexander Potapenko <glider@google.com>

Acked-by: Marco Elver <elver@google.com>

> ---
>  mm/kmsan/shadow.c | 4 +++-
>  1 file changed, 3 insertions(+), 1 deletion(-)
>
> diff --git a/mm/kmsan/shadow.c b/mm/kmsan/shadow.c
> index 6d32bfc18d6a2..54f3c3c962f07 100644
> --- a/mm/kmsan/shadow.c
> +++ b/mm/kmsan/shadow.c
> @@ -247,17 +247,19 @@ int kmsan_vmap_pages_range_noflush(unsigned long start, unsigned long end,
>         kmsan_enter_runtime();
>         mapped = __vmap_pages_range_noflush(shadow_start, shadow_end, prot,
>                                             s_pages, page_shift);
> +       kmsan_leave_runtime();
>         if (mapped) {
>                 err = mapped;
>                 goto ret;
>         }
> +       kmsan_enter_runtime();
>         mapped = __vmap_pages_range_noflush(origin_start, origin_end, prot,
>                                             o_pages, page_shift);
> +       kmsan_leave_runtime();
>         if (mapped) {
>                 err = mapped;
>                 goto ret;
>         }
> -       kmsan_leave_runtime();
>         flush_tlb_kernel_range(shadow_start, shadow_end);
>         flush_tlb_kernel_range(origin_start, origin_end);
>         flush_cache_vmap(shadow_start, shadow_end);
> --
> 2.49.0.967.g6a0df3ecc3-goog
>

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNMUFmnVweY5zCkkszD39bhT3%2BeKk1-Qqc0LZTUdPN0x%3DQ%40mail.gmail.com.
