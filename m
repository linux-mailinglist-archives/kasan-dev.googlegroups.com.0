Return-Path: <kasan-dev+bncBCCMH5WKTMGRBHWST6TAMGQEC2I7A2Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oa1-x3b.google.com (mail-oa1-x3b.google.com [IPv6:2001:4860:4864:20::3b])
	by mail.lfdr.de (Postfix) with ESMTPS id 6B0BC769D8C
	for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 19:02:23 +0200 (CEST)
Received: by mail-oa1-x3b.google.com with SMTP id 586e51a60fabf-1bf00c27c39sf619477fac.2
        for <lists+kasan-dev@lfdr.de>; Mon, 31 Jul 2023 10:02:23 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1690822942; cv=pass;
        d=google.com; s=arc-20160816;
        b=Ft485m8KWxOqsGXqtfaEq0rWeHTXqLU2cvRFuqQoNiBC1rmglhZAqQHiW94mZsZh8t
         rPZIghzCnKXUJf/XKi93tDxyVE88+L3EcxYT5i+vasQi3K0OqAyzvqMEgToe0zHaFwup
         BvtBhPpRbSASf0xNPELM+kU1SQKaWg/VIefy7YhaX/EFGeQ6RzW8t0WFUFlu1ssQkmBs
         178cXdSxD8UyveSR9ysEODjcy7AeBtjvxQtViAY0LCooz+vrtHSK8exdD6PLXw9QSLAn
         3OIwZT1F/yvO3vn8dkOuSEGRnT7nkCZKTJH4V7bXITqliwoh+ySpjSVlUrx4baieYh7E
         IaRA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=eDBjeh7C0DimSbvVjnYBFztFyMwi30mk34lghzTlABg=;
        fh=FpmOSBwjI87+MAeyVxOnHPZs0VsW7pD6MuuYSDRIGhM=;
        b=iUdl9LO7yes4yrUAQQQ0IZDtrN/yAnLsK745EnEkuOVTpKsVDbZNXXEZNkkBtLmwdn
         G3eKgonZP6TuMkw5hnm1WGGA2PLIbuqO1zse+RNUomoawZkAyYdfPJBocpNQXEKutr9F
         LA6KSUVth/jbw5/tv8DcNR8l9cuEHI1A9BG1TLmEJRwooXtatUBvEISvUeAKePKoQVoC
         xuU8k/MAY62upD19qpFK+9Wyrd4MEh1nnmwRYbBzZVfMXI4VuSK/6dN1WMmWfVB9ehh8
         uE1CisJz4cPUGWOBi2pLm+gFoCA/l2LeIY4Iu4E49AUHKbWufQIY3JyCSQogTfKLprNu
         zUIA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=VnMjq5NL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20221208; t=1690822942; x=1691427742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=eDBjeh7C0DimSbvVjnYBFztFyMwi30mk34lghzTlABg=;
        b=fwcSdh693+Tztb3hNu7JL70gi49TaSP46p7pZ15RZu/XTKyhPfEB/3OOPtBxUdwhfD
         HDwAfy64mTp9X2dSHwVEYYXOwElwgfctIV+mSNTUkZ0NnRE4j/nNzqEhddhhAtY5zfqb
         M03xZQ0D6tJRSdy9nr7DJQrBoHRarIVNPzcGsnIr04mf28J1JGu/emEvcEXoA0Irx0PJ
         dl8+7OWGZsHNubO4S/kiSryLu0dO15KnYbPxmMo5hBTem+hs1QxXhfT3LGCv2ytRMoaY
         W8YRon3tUDd6uqvO0V0iR1CaU20fpq3EwdNNVzNfNCWkvNiYv0TkSCLFDlA64JUUgGqG
         DQUw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20221208; t=1690822942; x=1691427742;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=eDBjeh7C0DimSbvVjnYBFztFyMwi30mk34lghzTlABg=;
        b=TEZ6KyuExhvnQdfJJ6djVawPfFqkbqMVbpY1CCplQl79PEvOiLVQkKmHGFHCEy031h
         /JICFWtHFJHMgKeapMeFFCt7zozVhjgo3CoMcqXkZSu/VsvGJa9RLjBC53oXHoRZTMQI
         jaYw0aVty+ZuFRsYg3MVg/zrOSpzqU+w0NuII+qmcHdPYXy+cRhY63OJgXyv83CZLakr
         93ew7Mbllw2C6r98AjjkS56KS5z4t5dYhNjn7XQbUej5uyI4JRW9becZbXwsruUk9Qvi
         ubw38XO1o+V7yNj9Ys6Piqmvyn0gQjmLziVAJ6gSvlkQl4bpHlIb4/ooF+vcojTw6rpS
         8Zpg==
X-Gm-Message-State: ABy/qLaM4CtjJnNugcYGFlh8Nl3PKN47UNAwX8Epf0npUcyTwvMnCUuz
	Bh4GNhi6QHO+CSLoXu2+n98=
X-Google-Smtp-Source: APBJJlFS0qzYUqQEjKBLR/7DZ6VWYFEL5ieDRq6PL1y1MiFOWdHXaCMgY19noTyLSFdh7WI+tNJATQ==
X-Received: by 2002:a05:6870:2047:b0:1bb:ac7:2e34 with SMTP id l7-20020a056870204700b001bb0ac72e34mr11430742oad.40.1690822942090;
        Mon, 31 Jul 2023 10:02:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6871:8a8:b0:1bb:6485:798a with SMTP id
 r40-20020a05687108a800b001bb6485798als1194642oaq.1.-pod-prod-02-us; Mon, 31
 Jul 2023 10:02:21 -0700 (PDT)
X-Received: by 2002:a05:6830:1e05:b0:6b7:494b:a503 with SMTP id s5-20020a0568301e0500b006b7494ba503mr9727704otr.18.1690822941516;
        Mon, 31 Jul 2023 10:02:21 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1690822941; cv=none;
        d=google.com; s=arc-20160816;
        b=lhaVjiw44fAeejTv7Kt3QNWCb6VcvofVw7gWMnze/vHFlzE+u/y1QYNkvs//3aDvM3
         +qRcwH5WeOfRYiyODxg8R5hIUR+d2or8/q90U76qEPRLZc/ZHCmuGK0r84U5KuaDmUSH
         YebNiCa5bk/YBFbuc1C6irUmVa8MdnEEEN47O8sPKzFo76ChSlNNnvfZZa/3/7uY6nKb
         oLy61Alr7VM4K/q9nqkTRRoOuDoW86eoJmR0jWiO0nJ4rji7TmDhsbyyp1T/LtNk9M/R
         Ql1Fn+LEX8PzWD9tG3ml/nAtCafGrk/t29mtA+7cHWCr9pLaQWL//9x4ZBzDpZSvnCd/
         R+Vg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=AE5derB4eYbJpu/3vlhDztTOvurVy780ibA6vwMtb3Y=;
        fh=/L/BfydENXJ5eWZhj6DuxRELOnbBRK5NL0Fx2I2Ns/k=;
        b=T0YGs9nWzoCbWerQMic1YGsjKH2TrNbEoX6SrTnAZRPC88utxA6wjGDPWAczHJxzdF
         ocHkSFIC9knF046iavRBodKmCf3lK9ZGK465RtEvl3bHwMhN6tdkMiswJblVTKBseK2E
         oKkVZWF1OaQ1QUSvJeXNKKCJ1KU/w/0fxYFTq5rdF5HTluYtaRlvpyR7iIAEbs8i6L9K
         aP64teaFCwKiu5/L0qYX+9eCNqXLBm3rxzXy7K4knUjqQEQdVyGfLNndP4I9KIiFg8Vk
         1Bee4KJCQBx/ibmF8jFzQq9mkYl/70iRuqMJB6gwnjqbA19HB/4oUtDDDNSoToW0IBXm
         xgeQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20221208 header.b=VnMjq5NL;
       spf=pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) smtp.mailfrom=glider@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-io1-xd34.google.com (mail-io1-xd34.google.com. [2607:f8b0:4864:20::d34])
        by gmr-mx.google.com with ESMTPS id l18-20020ad44bd2000000b006260dab0171si668020qvw.3.2023.07.31.10.02.21
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 31 Jul 2023 10:02:21 -0700 (PDT)
Received-SPF: pass (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as permitted sender) client-ip=2607:f8b0:4864:20::d34;
Received: by mail-io1-xd34.google.com with SMTP id ca18e2360f4ac-790970a8706so116113539f.2
        for <kasan-dev@googlegroups.com>; Mon, 31 Jul 2023 10:02:21 -0700 (PDT)
X-Received: by 2002:a6b:7d06:0:b0:786:f47b:c063 with SMTP id
 c6-20020a6b7d06000000b00786f47bc063mr9332620ioq.21.1690822940844; Mon, 31 Jul
 2023 10:02:20 -0700 (PDT)
MIME-Version: 1.0
References: <20230727011612.2721843-1-zhangpeng362@huawei.com> <20230727011612.2721843-3-zhangpeng362@huawei.com>
In-Reply-To: <20230727011612.2721843-3-zhangpeng362@huawei.com>
From: "'Alexander Potapenko' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 31 Jul 2023 19:01:43 +0200
Message-ID: <CAG_fn=Vm2-sckXeFhbbXekm+ENCjUnuX2rGb-gtPAZifS4NaWA@mail.gmail.com>
Subject: Re: [PATCH 2/3] mm: kmsan: use helper macro offset_in_page()
To: Peng Zhang <zhangpeng362@huawei.com>
Cc: linux-mm@kvack.org, linux-kernel@vger.kernel.org, elver@google.com, 
	dvyukov@google.com, kasan-dev@googlegroups.com, akpm@linux-foundation.org, 
	wangkefeng.wang@huawei.com, sunnanyong@huawei.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: glider@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20221208 header.b=VnMjq5NL;       spf=pass
 (google.com: domain of glider@google.com designates 2607:f8b0:4864:20::d34 as
 permitted sender) smtp.mailfrom=glider@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
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

On Thu, Jul 27, 2023 at 3:16=E2=80=AFAM 'Peng Zhang' via kasan-dev
<kasan-dev@googlegroups.com> wrote:
>
> From: ZhangPeng <zhangpeng362@huawei.com>
>
> Use helper macro offset_in_page() to improve code readability. No
> functional modification involved.
>
> Signed-off-by: ZhangPeng <zhangpeng362@huawei.com>
Reviewed-by: Alexander Potapenko <glider@google.com>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG_fn%3DVm2-sckXeFhbbXekm%2BENCjUnuX2rGb-gtPAZifS4NaWA%40mail.gm=
ail.com.
