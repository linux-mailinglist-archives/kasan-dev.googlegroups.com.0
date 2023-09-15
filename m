Return-Path: <kasan-dev+bncBCQ2XPNX7EOBBKM5SKUAMGQEFDBU4QI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wm1-x340.google.com (mail-wm1-x340.google.com [IPv6:2a00:1450:4864:20::340])
	by mail.lfdr.de (Postfix) with ESMTPS id F39BB7A2439
	for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 19:04:42 +0200 (CEST)
Received: by mail-wm1-x340.google.com with SMTP id 5b1f17b1804b1-402ddaf5303sf14235e9.0
        for <lists+kasan-dev@lfdr.de>; Fri, 15 Sep 2023 10:04:42 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1694797482; cv=pass;
        d=google.com; s=arc-20160816;
        b=0ayy9dwQeAWkZpxtJ+yuLhbht7mQvLJ15HWihHsZ0DFfE0Rtml1/ZahiZjjaimvTVY
         BAJdGOLCLZnfAzMxl4uLENJWY/rh9Mc8OQB7AygC9xF+t9iXDKFjYsEqsZLoUNwfAonw
         fMvror5KxXThFjlrf8tnh9hrzDKSVgal3m9rOxtKyl0QPhZoJ/WSnDdmrtjxUTE3ZAaF
         yp2aRe6BbXiY1fX4l5si7XZr5s3HShZic++QIcaic4HZat7OS41nZ7M2G6cRNn35BUF+
         ljfCPq4lQMyOSGaO7ZfpqttbNYfyS159YR58zN7PJz9V5W5mCzgrqcWt4SQJr44Vl0Fu
         SzwQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=SEqJWo6ECHaBZRNRlXaigPdPUev+4jB52lc1FbNp0bE=;
        fh=Qmk5EIq9HkvbtxDS99i47+N9jxVtMij8TCfWPNLVafc=;
        b=KJ4BQg5ggRPkNP4+/eNQyQUY0PmohfDhfupmUs9CqdDeiyIU33dg8oP9Y6JY6nJRG+
         oFGSEYiIAxe+g8y6gTqpcTu4XN4vBpvsLywrh8SYCst+ggnlc+26zJVFzM0mg53XQ2di
         Vd/cmr++a6hx30RimCmCFpxbvTqAL5ysy+DhHfiMJfVK/bzX16Iz8KL059+fEKKS7wDx
         1ohkrjN26095soceYchjSI8BlESMm3I8gm8/Uu+G2fb28q/hnEfjZqUB3fzf4RYnquZI
         nJz6ovOCLXAiz1ucg5Qk1lYvLbQC4UYTglu3oza6+E3qKNhf9qzTMOf6vBCDO+BO2vVN
         7PPQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v8ZHR3FH;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1694797482; x=1695402282; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=SEqJWo6ECHaBZRNRlXaigPdPUev+4jB52lc1FbNp0bE=;
        b=MAL5JC1mvpdv1WCK9LL+slFYQkAJbzQVhpFLIseJT1FNToaMFG59HnBdG8VTir6ago
         +RtOSI/e/QnpTlPU3Yb7sWXp/dUE28L485/ozXJtd+Ly6perxdL5fPAZsD780j4A3HSy
         0TFZY9j3KZ23Md51HbZdXFIJP4o1P7cY1D3HE4RjN0CogwxaFdiVZRljWzJBAY+svwi3
         62I/+9gKhLXrtjfA6BVBqNalQ6zWdfS0cLFXuRz9/j2QD4ryM1XshJ9jNTHrkfb+exhx
         lqIazPcCKEZTIXDdGLwqP34JMKZ7s0BA1foZzbWVkTiVV4pQIgS/svs8rjJ1vat/G/79
         O5IA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1694797482; x=1695402282;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=SEqJWo6ECHaBZRNRlXaigPdPUev+4jB52lc1FbNp0bE=;
        b=h8s4nzqwTcmjRWVu/HvKwQgZyKDtSlSnwYeC1j0sW7ttHfRJ53jmFA9A8nBbOVj9E3
         2Lp+RYgKTVEDYwOOgh4vNGXB7ZK+79PYMqZkAnGA/AU3Tw/wVLMSkGhoKLrZ4hleFw8+
         jJR24i/4FrB5FSyywPL1maj6SXHCfqCcMouh0wKkbuQqHV813XYRvtXcIYI+JQhSDrhz
         lkCQgBHggFAhmeDRBe04ckWH/5Vh9zgMt7GSZGJgFh5DpbLim/NkETEAXQsL4QV6jZA0
         qEwZX4FksoOwdNjTLkmJW//Q7IL6tvFNpVr6DEaI7WI+32KwleNCCAzp28WBjnkiEuAX
         h5nA==
X-Gm-Message-State: AOJu0YwWLMHlbbdArXLpEtGbboBIs/CT1VgmhZbnNjjP3vdwJnYQRCLk
	T+misMcteQOHKUBBvaG2U7I=
X-Google-Smtp-Source: AGHT+IFmlRrdoqAB3lW57i5dcqCOX4OT4B4CTGgB2hKYkxHhYeuiw/NzxfasttapFluupN4ZaxWQmg==
X-Received: by 2002:a05:600c:1d9d:b0:400:c6de:6a20 with SMTP id p29-20020a05600c1d9d00b00400c6de6a20mr2759wms.3.1694797481587;
        Fri, 15 Sep 2023 10:04:41 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:600c:4f87:b0:400:2531:251 with SMTP id
 n7-20020a05600c4f8700b0040025310251ls1246644wmq.1.-pod-prod-06-eu; Fri, 15
 Sep 2023 10:04:40 -0700 (PDT)
X-Received: by 2002:a5d:4591:0:b0:31f:e418:223d with SMTP id p17-20020a5d4591000000b0031fe418223dmr1687090wrq.7.1694797479921;
        Fri, 15 Sep 2023 10:04:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1694797479; cv=none;
        d=google.com; s=arc-20160816;
        b=TIOFxIiuIr2JYYldvE0lWb+4473E2CYEh+bMlq7ranwXeadcNDVWyxIdiNe5jJFwIY
         FF3pF43B46Fy3C29EskrF7NLrIEYDGkO8S4y77SgXa3snEiO1aCjlbUShuf5nn42lpHN
         QD8yrwm1sneIdnGrk+GnaN6VD1SMDKvgvAa0AKPOmgtcPN7FdsIcXV1P63eAm4HTrAIc
         sEiDWdH1Bxxr7aNKfA4K2Dhoq5NJVvQPyprQuuG6cpjpaON4hYXcSmxDvZDA/u2w4DKn
         LHHp703GNuqKWa72rTpi0xEdRRiwAT1jDSYXOAZCDZeipzIgqrIvxQYx6a7AGXZ2lMOQ
         OSCA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=LlAvjtLPcGmDg4A7voaF5Wo0HxRPXZyKmdzluEIsWow=;
        fh=Qmk5EIq9HkvbtxDS99i47+N9jxVtMij8TCfWPNLVafc=;
        b=UU8KNGYC5P8f5Y/W3oJkKdzbQM37BgkwS5CCmtwvwBxVxfQVh7Z9MqLQJd5vfLmIIl
         V/8JUk21IDQtTSksUnio+gAfsZhnn5Me1nW8eL57lmjeqg2mh2mA3KaWsahbXmRKmPaH
         hHHdeZwcSmrejZ/zWdsNMBElddfMEwGE29/R8Uo6vgdioWXzDT16H14LFnbmWPHAFWib
         LUbib3dIrNLYVG5NHuSewc/xmSd+dlb82XglIiXN6NyAOzeQuteMeLN4DQNIzvyZJeG5
         rHDdHDokyMKqIsL/WywfGbhHgcZtfm4MGnY2e/crn9JzPBNU5FD5Ia3u42qcMqbjwycn
         g+nA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=v8ZHR3FH;
       spf=pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) smtp.mailfrom=jannh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wm1-x32e.google.com (mail-wm1-x32e.google.com. [2a00:1450:4864:20::32e])
        by gmr-mx.google.com with ESMTPS id bn20-20020a056000061400b0031de9b2a3b2si246970wrb.6.2023.09.15.10.04.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 15 Sep 2023 10:04:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as permitted sender) client-ip=2a00:1450:4864:20::32e;
Received: by mail-wm1-x32e.google.com with SMTP id 5b1f17b1804b1-4009fdc224dso1185e9.1
        for <kasan-dev@googlegroups.com>; Fri, 15 Sep 2023 10:04:39 -0700 (PDT)
X-Received: by 2002:a05:600c:1e07:b0:3f6:f4b:d4a6 with SMTP id
 ay7-20020a05600c1e0700b003f60f4bd4a6mr2391wmb.7.1694797479400; Fri, 15 Sep
 2023 10:04:39 -0700 (PDT)
MIME-Version: 1.0
References: <CA+fCnZePgv=V65t4FtJvcyKvhM6yA3amTbPnwc5Ft5YdzpeeRg@mail.gmail.com>
 <20230915024559.32806-1-haibo.li@mediatek.com> <CA+fCnZfuaovc4fk6Z+p1haLk7iemgtpF522sej3oWYARhBYYUQ@mail.gmail.com>
In-Reply-To: <CA+fCnZfuaovc4fk6Z+p1haLk7iemgtpF522sej3oWYARhBYYUQ@mail.gmail.com>
From: "'Jann Horn' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 15 Sep 2023 19:04:00 +0200
Message-ID: <CAG48ez3GSubTFA8+hw=YDZoVHC79JVwNi+xFTQt9ssy_+O1aaw@mail.gmail.com>
Subject: Re: [PATCH] kasan:fix access invalid shadow address when input is illegal
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Haibo Li <haibo.li@mediatek.com>, akpm@linux-foundation.org, 
	angelogioacchino.delregno@collabora.com, dvyukov@google.com, 
	glider@google.com, kasan-dev@googlegroups.com, 
	linux-arm-kernel@lists.infradead.org, linux-kernel@vger.kernel.org, 
	linux-mediatek@lists.infradead.org, linux-mm@kvack.org, mark.rutland@arm.com, 
	matthias.bgg@gmail.com, ryabinin.a.a@gmail.com, vincenzo.frascino@arm.com, 
	xiaoming.yu@mediatek.com
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: jannh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=v8ZHR3FH;       spf=pass
 (google.com: domain of jannh@google.com designates 2a00:1450:4864:20::32e as
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

On Fri, Sep 15, 2023 at 6:51=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail.=
com> wrote:
> On Fri, Sep 15, 2023 at 4:46=E2=80=AFAM 'Haibo Li' via kasan-dev
> <kasan-dev@googlegroups.com> wrote:
> >
> > The patch checks each shadow address,so it introduces extra overhead.
>
> Ack. Could still be fine, depends on the overhead.
>
> But if the message printed by kasan_non_canonical_hook is good enough
> for your use case, I would rather stick to that.
>
> > Now kasan_non_canonical_hook only works for CONFIG_KASAN_INLINE.
> >
> > And CONFIG_KASAN_OUTLINE is set in my case.
> >
> > Is it possible to make kasan_non_canonical_hook works for both
> > INLINE and OUTLINE by simply remove the "#ifdef CONFIG_KASAN_INLINE"?
>
> Yes, it should just work if you remove the ifdefs in mm/kasan/report.c
> and in include/linux/kasan.h.
>
> Jann, do you have any objections to enabling kasan_non_canonical_hook
> for the outline mode too?

No objections from me.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CAG48ez3GSubTFA8%2Bhw%3DYDZoVHC79JVwNi%2BxFTQt9ssy_%2BO1aaw%40mai=
l.gmail.com.
