Return-Path: <kasan-dev+bncBCT4XGV33UIBBI6HV6PQMGQEJOIB66Q@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ej1-x63e.google.com (mail-ej1-x63e.google.com [IPv6:2a00:1450:4864:20::63e])
	by mail.lfdr.de (Postfix) with ESMTPS id 16B9A696E05
	for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 20:40:20 +0100 (CET)
Received: by mail-ej1-x63e.google.com with SMTP id wu9-20020a170906eec900b0088e1bbefaeesf10724227ejb.12
        for <lists+kasan-dev@lfdr.de>; Tue, 14 Feb 2023 11:40:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1676403619; cv=pass;
        d=google.com; s=arc-20160816;
        b=nXUUCew2faA0s89+X5og+9AtkeuNeQ8QSy503pd94gPWHrkyU14kucMu7U7Kt0cTs8
         wxyABp813XzbQCME0npVGlzYx2Lg0Bud0DcXM5zWgwHBvSM89X0nTwBRQBdClNnqys81
         QHk55/W1/PzQBQCzFNAjIkrbT1adrIuv0VyyhZF28fTNZx4xPgDJ2KNis6rlQxOJsjL+
         u/lsCF3xOlPHbpbjNgZ0OZwXYI8q+uIj3JTVw8Z3h5dZOQ/nsDaT6RT8AN0DaV/sb6M8
         O3KFbAtYknpfZZXz4phG4NjYHsbqmtZvuX6+v3v+gYFEcj8Ozz4lgQ3NiIKVRbXbsN8J
         r0iw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:sender:dkim-signature;
        bh=7a5BzEZ4maH+vBTbMyszgRN0ZMXa63i7GrJGLB/2cDc=;
        b=Nhil4fdBorr9a/bLnJYrYhDGWM2AaQGjjiTKZQu9Yw6W7gsNBo+wdRp1t9sYT1JHyj
         sNx8VwusRhyKbcYNISNx8EdVh5KF1SMgTQ6ke6DlVPp1HrlYU7lasJJLN/ovgcMmIDUs
         emoCn4gvAi8LG69FARIy0qeQ+ENuJqDu7+pPFbA6xgvFBqTqzlzOlAssjXwtcSgcP5xS
         SXexCElkmXQBHx4efQk0MPE0KdPg3j3SrFB3+rxiTEHZd5foQao3tjF+JzG/XxvuRKoq
         NgZYis+lb8LCWST6VHQtXHYJVuOCb/bfJJ7zckT0hFh+Hgp/EcK0sNsoT9x8fKmPHEj+
         TpKw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cp605a2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:references:in-reply-to:message-id
         :subject:cc:to:from:date:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7a5BzEZ4maH+vBTbMyszgRN0ZMXa63i7GrJGLB/2cDc=;
        b=ZaIjpZ5cBFNbu5BWP2DOZBEAt6N+kWDE7W9OEQPZivV25Ivn4LGnr4fT3E7QaBuRXY
         Us8C6bMmr4rGUZGiC9OWZ6ixg5/QyKA+rloBfCK0Hrm6FXnqs26o6wrzXeEz7calen0n
         zGIPtqw3PLrzggdmC08mSLgtH/VEyU1MReaeSakvwiu3baaI5RuFPXH43BoequmWbcYe
         QTreqE44UgSG2DQ7+0gk0T1rkDVyFouHQZLtwcFsWUqZo8nFoyRF41GQ/CE6UH235qiw
         LO3/DiRaESzOcow4RczcrJmzbfEZaTDJMwFZnRUJVMSeRS3jtwpSpTyQFI4EOrUMjVP2
         z8bg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :references:in-reply-to:message-id:subject:cc:to:from:date
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7a5BzEZ4maH+vBTbMyszgRN0ZMXa63i7GrJGLB/2cDc=;
        b=FlgpY+AaHGXjSwZxnCZAwTDtWtnahdZalHG0x3g2EjIDeZtsCha5tsSblSOSP2DA/8
         q/WEjWan+CquF/Saon448w+rED7eGXtH65uDLtdwru5fvbWxxtsMvwjZMHpy3UMCtbyi
         JpP+b6aZlokrRPP+/n+8C06trvOzKdB2nHa075GEGj4aBNc/a3sMmcJggzAOpRFXy8i/
         wkD54LRY7k44pvfcxlxP8j/7b8/GJe8f8xBLyi/Dh1ralF9ZWu2gVTYUyTcbUmktGXuG
         z1Z9N+FjwNAoEPRPZZBrijw5SkAjdRCYRF+rnY+xhrSxZR5/5NCjPP7SeXIn3BZ3Ea4f
         K3Qg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AO0yUKUE9j7YNomcvDMpwJffh7M3Xawf78uAXcVlRCmIJyfgRRByvtPo
	HQcjiV0gnrow3ZWoq5nFRhU=
X-Google-Smtp-Source: AK7set+wR9svWYcecFuEQtfgAmcR9YEplt+DXU5DW1N235+GcRQJWuQbnex8+gjQvOE11qKLsGgZSA==
X-Received: by 2002:a50:d70e:0:b0:4ab:3a49:68b9 with SMTP id t14-20020a50d70e000000b004ab3a4968b9mr1790085edi.5.1676403619451;
        Tue, 14 Feb 2023 11:40:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6402:17d6:b0:4a1:ec52:2ed5 with SMTP id
 s22-20020a05640217d600b004a1ec522ed5ls2650461edy.1.-pod-prod-gmail; Tue, 14
 Feb 2023 11:40:17 -0800 (PST)
X-Received: by 2002:a50:d50b:0:b0:4ac:bbc7:aa8e with SMTP id u11-20020a50d50b000000b004acbbc7aa8emr3439663edi.41.1676403617900;
        Tue, 14 Feb 2023 11:40:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1676403617; cv=none;
        d=google.com; s=arc-20160816;
        b=w4CpYcsu6mzWvzsMiJk9K2/r/Cmlikvv2MuQRwbdCWNlPAJwdAioPvaVMgyvY0L1yS
         I45inHehJB8dN6bGlejexMsL3dAnlf5pdLVhgnlrQdEHkaNe2wKbMqFlVohE1P+xfRRI
         7dVhD6qiIzyUN0eNqwXBGMNRfhnVe6YdHALxAbYFwwmtpAaLvIk1bdxWdYrNhqJ66h2Y
         5ZP/fdVYo6GKgLtvBVwU3QH6Ws7pleet+RGQB1wIi01IhxWjCI+g1D0ApfCt0V6WjdFn
         anxon3iBWobjCOjA6W6GwMSQwcZUzCzdtd3Qkn46/mmKvtT7jfImF3pmpm3/XRx2FPn7
         sxrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:references:in-reply-to
         :message-id:subject:cc:to:from:date:dkim-signature;
        bh=Op13fe7cM0WW9AFf3mRMjOqBT3cIvQfmgUIRH6wk7tQ=;
        b=sSECmZmABpSCcuOSl3UK6ID3PcGFqgFezPn/zCFzg/IS1MKUBzu3xXtEaWf8OdRt0x
         BGsbyGXE63gPDtyWM9TwRsIwZeZWZ6aL7sPEXfww6PDkfCpMoJHs5PJM9Hoh1hGD6g8J
         fK6WqU9xTzmv5sv3ulEZUQre8HwkEazIdyY1OErAJxGTRiqONO3nH+2VxHPvfymiV6bS
         3GBqZ2MOtcYPf3mrPBHGGupPLZKO0x/GIFxcuUJ5RTZBSbCtWU8tHBlrIX/5Yok0ocQP
         HLnIZv0KX0xpvhBWijTMzkcgE8VBSe8V+KR3LOH3Gi79Xa4JK2q6O5Iht3wGywDhG4AE
         OMNQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=korg header.b=cp605a2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
Received: from ams.source.kernel.org (ams.source.kernel.org. [2604:1380:4601:e00::1])
        by gmr-mx.google.com with ESMTPS id d11-20020a056402400b00b004acd48ed527si224444eda.5.2023.02.14.11.40.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 14 Feb 2023 11:40:17 -0800 (PST)
Received-SPF: pass (google.com: domain of akpm@linux-foundation.org designates 2604:1380:4601:e00::1 as permitted sender) client-ip=2604:1380:4601:e00::1;
Received: from smtp.kernel.org (relay.kernel.org [52.25.139.140])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ams.source.kernel.org (Postfix) with ESMTPS id 5736CB81ED4;
	Tue, 14 Feb 2023 19:40:17 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPSA id 8A6F9C433D2;
	Tue, 14 Feb 2023 19:40:15 +0000 (UTC)
Date: Tue, 14 Feb 2023 11:40:14 -0800
From: Andrew Morton <akpm@linux-foundation.org>
To: Arnd Bergmann <arnd@kernel.org>
Cc: "Liam R. Howlett" <Liam.Howlett@oracle.com>, Arnd Bergmann
 <arnd@arndb.de>, Andrey Ryabinin <ryabinin.a.a@gmail.com>, Alexander
 Potapenko <glider@google.com>, Andrey Konovalov <andreyknvl@gmail.com>,
 Dmitry Vyukov <dvyukov@google.com>, Vincenzo Frascino
 <vincenzo.frascino@arm.com>, kasan-dev@googlegroups.com, Vernon Yang
 <vernon2gm@gmail.com>, linux-mm@kvack.org, linux-kernel@vger.kernel.org
Subject: Re: [PATCH] [RFC] maple_tree: reduce stack usage with gcc-9 and
 earlier
Message-Id: <20230214114014.4ce0afb658fae97d81f32925@linux-foundation.org>
In-Reply-To: <20230214103030.1051950-1-arnd@kernel.org>
References: <20230214103030.1051950-1-arnd@kernel.org>
X-Mailer: Sylpheed 3.7.0 (GTK+ 2.24.33; x86_64-pc-linux-gnu)
Mime-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: akpm@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=korg header.b=cp605a2O;
       spf=pass (google.com: domain of akpm@linux-foundation.org designates
 2604:1380:4601:e00::1 as permitted sender) smtp.mailfrom=akpm@linux-foundation.org
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

On Tue, 14 Feb 2023 11:30:24 +0100 Arnd Bergmann <arnd@kernel.org> wrote:

> From: Arnd Bergmann <arnd@arndb.de>
> 
> gcc-10 changed the way inlining works to be less aggressive, but
> older versions run into an oversized stack frame warning whenever
> CONFIG_KASAN_STACK is enabled, as that forces variables from
> inlined callees to be non-overlapping:
> 
> lib/maple_tree.c: In function 'mas_wr_bnode':
> lib/maple_tree.c:4320:1: error: the frame size of 1424 bytes is larger than 1024 bytes [-Werror=frame-larger-than=]
> 
> Change the annotations on mas_store_b_node() and mas_commit_b_node()
> to explicitly forbid inlining in this configuration, which is
> the same behavior that newer versions already have.
> 
> ...
>
> --- a/lib/maple_tree.c
> +++ b/lib/maple_tree.c
> @@ -146,6 +146,13 @@ struct maple_subtree_state {
>  	struct maple_big_node *bn;
>  };
>  
> +#ifdef CONFIG_KASAN_STACK
> +/* Prevent mas_wr_bnode() from exceeding the stack frame limit */
> +#define noinline_for_kasan noinline_for_stack
> +#else
> +#define noinline_for_kasan inline
> +#endif

Should noinline_for_kasan be defined in kasan.h?  maple_tree.c is
unlikely to be the only place in the kernel which could use this
treatment?

I suppose we can do that when the need arises.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20230214114014.4ce0afb658fae97d81f32925%40linux-foundation.org.
