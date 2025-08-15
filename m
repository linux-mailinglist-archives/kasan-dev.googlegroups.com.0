Return-Path: <kasan-dev+bncBDW2JDUY5AORBV7V7LCAMGQEXCJ6CTQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x33b.google.com (mail-wm1-x33b.google.com [IPv6:2a00:1450:4864:20::33b])
	by mail.lfdr.de (Postfix) with ESMTPS id 3D57EB277D4
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Aug 2025 06:43:05 +0200 (CEST)
Received: by mail-wm1-x33b.google.com with SMTP id 5b1f17b1804b1-45a1b0b46bbsf7181885e9.2
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Aug 2025 21:43:05 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1755232984; cv=pass;
        d=google.com; s=arc-20240605;
        b=apDAR/3U0T4eM1myI21qfW8HiMIcUb1EhWCBBqBTCwhOM68IbFXaKRLRUT3UFGTAc9
         HlvEtP5qkQ3i/bSZUbjbt45hWh4npm6jj8MByFxViiwHGeFLYqupKXV6FZJsuWzVXBhT
         z6Z3CpV3MT+0YmgtpsTtASDxIRbi6623D/NeZDgvz2IXvi5C2iI09CR3yRKaymFhs2da
         gEYZFo6LI77V2l3tuyhegejBGV7wHjngbc7By369t0K5qiwZQ3143W6X/gGAg7xN/vHI
         jWAT5jmrpzkCoQDUik5S+U2PPDph7FiMgkgQSA5o0DjIDVm58XQ+3UlDICpP90gSmqfp
         uZOw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=ntsU+snG0bbLkv/rzbLmJ5JcflrbLeoMKLR9FQiROIo=;
        fh=sCIf0S6YnMxNaTE0qjAPG99a8lxOPyCSfDwjvhhTvHQ=;
        b=HRyzrG5WhX4CGY7B5wLSwZu2p8ljDvQZh88TTSCpehTyYv9oR+Bm1fssLjde8YvVXN
         bgMk1PAK2j/HyNuaVS6WvkMbPsLCsjrngqVSMmnN2E29MLNfGijHbHmWGu/lPdcUMYwR
         m9OT1NXC2Ws5f3IWZH0RL/NZZgurin915yZghC9RyQsvn6t3MWTq2v/fqYtyrZVdWkq2
         TrRuIxyI7pc09hOE+OQbvPZ8qTwedl4RuLCR9V8thZ080uFXqi3p+okrf4uN6XXClZuB
         IbramZ+ef5a3qmxMpCRS63a7XbXJdhv9zD3YYIbBq+Psf+66ZuqAP0U/DdfL+ZbCRknm
         bNCQ==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iMFgnhjf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1755232984; x=1755837784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=ntsU+snG0bbLkv/rzbLmJ5JcflrbLeoMKLR9FQiROIo=;
        b=UmO23rfCFHyMspgVaJY9XCELR5cuJ7vj0Jbxw+b8KKx9KdFfEEQaY5wDVko7paYhoJ
         EXDQBam6A3cjvsNbjyZVPFe5AQUp+oGXNVj22UK3XRvd+bx15r6M2utotEQyJOWzHWzZ
         B/Cin92c+Gvd/TGhf9RB4Lc8PpQoWoEc3AOqSxqLoC6Jip77XV5tQkUYVacyIUQ4MEk6
         iTaUrev35Uz3Z/4NpAJEDlmBjARMMj2QrChlRkjdkWsVLRDmqestbKeOSkYws1BatLmv
         EWqRoo/u7jbG0S2vArknOK+i8MXdKQtJESIn3aZU7xzff/HU/bskJHfLnGBf+2kitc4W
         EQJA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1755232984; x=1755837784; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ntsU+snG0bbLkv/rzbLmJ5JcflrbLeoMKLR9FQiROIo=;
        b=OpwpuDfLwDDCDehb9YYyiMR8pUls2mCDKX+nuosYcgdvc85hWtB66zcRa0Pkam4oHx
         gzBf/NFlIt+lVKCa/1wbnR6QqnRLVDy4Xai7t30N0ThrfpFpXTSzjCqW5SOq+w++Y42g
         gakyT584OhwWKWAHkgKPrd1R7GRFmfm3rYvzRsB9UXghKjFXmRTKzYPrx675TPpC2Kys
         p0J1SuLivPdbBILc5iOQh0Q+g2fzfkDvIpXPRyeuzQfZat0cz4DFhgeEh5TPDNR29t4o
         ZfGqvLHmsWlA1Ib9Y9b/F069Pds+MzY8vbr6WaKmf+hxXil/llwMho5jZnKus7uY9uZK
         C+3w==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1755232984; x=1755837784;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=ntsU+snG0bbLkv/rzbLmJ5JcflrbLeoMKLR9FQiROIo=;
        b=G+Ai56CGn4fqoTHamlLBBAtpehqvniOiB2B2zao4gHeb0t/UmVvuwV9mgMzj6O5MBo
         7D7jRDYfMyrI/9+cCtLpyyDkONNdiqmWqObknxxEsnrIBzIyOzuHMxOAcV1VqD1ovSaI
         71QXjYv3nsroMECcLo01h36DnAIAkjlclpjgyYq9aNG3yHEsYR4WrMIEK3Gsg3wEjX31
         VcpuhVHEuahg95YsK2DSN1YSZd6Iq188cQLmcxkPH/AqzE9j8KB2meDWYMKu57r41wsf
         Y5gqom1pIEusKmFTmanK7ZjA29QvvtYBtwkp6qdxzl/l5kxA8vkVJc3YTyDOBqKL74gW
         HV0A==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCUFyyCxd0nGWtq9X4EwWKb1XGd/rsaS9QgCppZDQO9xyVSnY2uFhcfYw18okWMWRYtWnP6PIg==@lfdr.de
X-Gm-Message-State: AOJu0YwWm/6uIupznNcx3R+8euxueJ63UIYCr3pF2moLuNd4od4GvyD7
	TbpqExqeojgvL9aDrJaSGZkG26hw1sNzL3ysQvqWUnvOn9SFvVS8YRtV
X-Google-Smtp-Source: AGHT+IH9SKsukK3zHIsYnmTh74Wo+7uhC5+QnzSJkJ/HrdN5A51RLZGZRDTBb8nzoV7RNkpF5ZL7RQ==
X-Received: by 2002:a05:600c:198e:b0:458:a559:a693 with SMTP id 5b1f17b1804b1-45a2183a0c8mr5777715e9.18.1755232984358;
        Thu, 14 Aug 2025 21:43:04 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com; h=AZMbMZcikQ5HqkXxawsuRGu2ez5Y+UyrPWHo+ONuCLttBfqtTw==
Received: by 2002:a05:600c:35cc:b0:459:d43c:9643 with SMTP id
 5b1f17b1804b1-45a1ae5836dls8044135e9.2.-pod-prod-03-eu; Thu, 14 Aug 2025
 21:43:02 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCVCkk9cb2WgnpAJMnG5Axibj2D253QPp0ZIy7UPuDHB1GgEky87PUPV96EKxNUYch43eEBW1X3dUc0=@googlegroups.com
X-Received: by 2002:a05:600c:4451:b0:459:d8c2:80a6 with SMTP id 5b1f17b1804b1-45a21864e1fmr4810545e9.33.1755232981813;
        Thu, 14 Aug 2025 21:43:01 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1755232981; cv=none;
        d=google.com; s=arc-20240605;
        b=ih5zkahHAB7y3THpVWvxus3q9oOxBiqsnthQWssa9TUruF6y/aeC+0I63En4ph/87w
         3+i+LNPtTxky39HeW52YyYzJrgV5Dl0yeByNXZhZd7/4YpRCO14xepbFk9aPgHPMnCeS
         N1ZezbtBo5ESFhMsNkssFA7tIkiyFSWlRTchi8wUF5uOjXAfm0HjRDrxq5M4ORkGCewF
         8IiF+idY5TaaCe+8imuvx8Ix4Qr/xnP6pduJ737Ogwda1ULiaNSfODTmVgyE6BqRnukY
         PpNLCT6mL4NPsIvQIdErK2z3SRtrozv10DjJ3YT5uf8+OGuY0whgpBfTeM+z783/A+jz
         4nNg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=j3R7e/mODk8uXckZ5NZ5/I3y0JpUqVHIYps8pPNWoCs=;
        fh=wyuVRC83sXVqWFsf6gbb17e+A+lAVmfjWrk3vxpydMQ=;
        b=gB8CeJ3xSeQju9jjKcfwrF1MbsrxI/MIU2Q6CsqBZJjt0AcmHlRTZ+L1bgXOnM1D/s
         6CN6221nrk2/Uad/mmRloupI5eBm6xU4MYz3wrienh0abpB0nWb+863G++vqI8YoF81W
         rxMo4bVDIuevOjPvQuSQ1LYC+0HgEyi+BhiqPWxo0A1lRR2YCngZndPCkojG7Cxbit7Z
         bQ+ES7M2cIpOrIR+rxwJAb9LVBbTdHqkr1Y3ODtrblQKmnLF5lCad8fb4K+ivQ9wSNJK
         ACimYMQcycOyd3/ritAUxpSrOWDHYXzfbnRp5Wt05fU6YW8Sl4YhqeREK7Gc9c9cnbXQ
         +Vng==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=iMFgnhjf;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com;
       dara=pass header.i=@googlegroups.com
Received: from mail-wr1-x42d.google.com (mail-wr1-x42d.google.com. [2a00:1450:4864:20::42d])
        by gmr-mx.google.com with ESMTPS id 5b1f17b1804b1-45a1b90c155si596045e9.0.2025.08.14.21.43.01
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 14 Aug 2025 21:43:01 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d as permitted sender) client-ip=2a00:1450:4864:20::42d;
Received: by mail-wr1-x42d.google.com with SMTP id ffacd0b85a97d-3b9edf36838so974871f8f.3
        for <kasan-dev@googlegroups.com>; Thu, 14 Aug 2025 21:43:01 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCU5EClNg765vKbVowIm3WOMSg+bgu+VCQIC2nDqSF2N5oER+8WBFRC09D37Gi2GPJO7ZwQ6dixlFk4=@googlegroups.com
X-Gm-Gg: ASbGncvgrvQqgERzcoYLjPN7xki5kNilCjM68yduJGEhR5uK+ojWkViKdyo0Dw+IBsu
	u+0tkCjIKpAAkIXs9TPI/RpWP5zROhtuDdfnxHokI09NKWBbVdKqfB+sMO5zJPh2czkXkpH1zHv
	hPfBMq9YohzWu4BCFSPmU6Ummw61eVN0QGf8snlpV3TClFcSN6kOBnfB5q87g6Mcxp0tSn1kGWT
	CyBAiUN
X-Received: by 2002:a05:6000:4022:b0:3b7:899c:e87c with SMTP id
 ffacd0b85a97d-3bb6636cd4dmr361412f8f.2.1755232980929; Thu, 14 Aug 2025
 21:43:00 -0700 (PDT)
MIME-Version: 1.0
References: <20250729-kasan-tsbrcu-noquarantine-test-v2-1-d16bd99309c9@google.com>
 <CA+fCnZeuewqXSW0ZKCMkL-Cv-0vV6HthJ_sbUFR9ZDU6PmzT-g@mail.gmail.com> <CAG48ez0OnAPbnm73a+22mpBjvGHKFGqYAA8z+XocZEHXJCcQiQ@mail.gmail.com>
In-Reply-To: <CAG48ez0OnAPbnm73a+22mpBjvGHKFGqYAA8z+XocZEHXJCcQiQ@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Fri, 15 Aug 2025 06:42:50 +0200
X-Gm-Features: Ac12FXzBCNI4JKiPn_2WUKTuherdT8IB-yvUU_GUQLdNyBF0zRHg-bm_iV4Kkkc
Message-ID: <CA+fCnZcYBCfPA5ObUEWq9iJnXFMw95GKHFZaaZPr84GUtbVNnw@mail.gmail.com>
Subject: Re: [PATCH v2] kasan: add test for SLAB_TYPESAFE_BY_RCU quarantine skipping
To: Jann Horn <jannh@google.com>
Cc: Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Vlastimil Babka <vbabka@suse.cz>, kasan-dev@googlegroups.com, 
	linux-mm@kvack.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=iMFgnhjf;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2a00:1450:4864:20::42d
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
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

On Thu, Aug 14, 2025 at 5:05=E2=80=AFPM Jann Horn <jannh@google.com> wrote:
>
> > I think this might fail for the HW_TAGS mode? The location will be
> > reused, but the tag will be different.
>
> No, it's a SLAB_TYPESAFE_BY_RCU cache, so the tag can't really be
> different. poison_slab_object() will bail out, and assign_tag() will
> reuse the already-assigned tag.

Ah, right!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion visit https://groups.google.com/d/msgid/kasan-dev/C=
A%2BfCnZcYBCfPA5ObUEWq9iJnXFMw95GKHFZaaZPr84GUtbVNnw%40mail.gmail.com.
