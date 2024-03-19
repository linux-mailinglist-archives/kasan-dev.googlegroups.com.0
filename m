Return-Path: <kasan-dev+bncBC3ZPIWN3EFBBVVB46XQMGQEFM25TDA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x23c.google.com (mail-lj1-x23c.google.com [IPv6:2a00:1450:4864:20::23c])
	by mail.lfdr.de (Postfix) with ESMTPS id 75FBC8803EA
	for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 18:52:24 +0100 (CET)
Received: by mail-lj1-x23c.google.com with SMTP id 38308e7fff4ca-2d47e55e058sf43405851fa.3
        for <lists+kasan-dev@lfdr.de>; Tue, 19 Mar 2024 10:52:24 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1710870744; cv=pass;
        d=google.com; s=arc-20160816;
        b=gC9+Z9TGFgYIozWt0Bkl8AfWyRHjnpCsdVu9Cqu8xc3dVI6ZRZ7FeCg+Q/u0Ss3l3Z
         3316RkdccVvxNutRLp7Re7kfX/frll99FvTg3lvEhJlzXAHKQD2CfU4pyLAmSTRQWCr7
         yFT35kO35fExE9Tanqt+m90OLffl21hU+hNkpmQWKT257odH9x2BV0QudNMrEpLmSSR3
         GseduwJP6uK33S/2xfAn4RihdO3t8vuptbHr2gArGslAE194yAnE0XFq/A/oKBpGMRh3
         GbYV5Ol74BoEUP8jX47Nlu9Ve8AR6U8DQVA908eDO+h1Pgoavp1O1y+fcix1fm+d7Pwv
         RhfQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=7NZdlDsf28pYdWfxYOgJXECtQ8Kh95rnKbeg37TkrSE=;
        fh=x2XLjNmRP6WMeFrmxZsjFLa+1IDG55y38SyiYYMgtZM=;
        b=qds9Sk1WWtDIJT788ri4H2/vKLKI2yq5H5Qm7XNZjPXOmjtXqPYQZTXyPwXEPNNiJj
         axwXEBOgPSiCTIC1J4s9N8MDlHbDrH9yGsbX5kZhUqhprYXrX0htV2+QUWvnFL3OdpJd
         X3drYqx/++VDralMPM00ErADxebh7D7LQYkegw9d3R8m2AWkjo96CouV6DrpJnIElEVV
         abdRCgopawW4e4DnpH1/b87GeHcXlhkcWD+ROlWNLic/UepHsF0xuV5AYFgjOvHfj8bi
         GH21Si0QZQBWg7QeSKHDIqQtlSyqQ92CBiLQcA6tuRxFN3rQowF1sXx0JiIkZzBpcuZo
         Vztg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=MPP0cAyX;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1710870744; x=1711475544; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=7NZdlDsf28pYdWfxYOgJXECtQ8Kh95rnKbeg37TkrSE=;
        b=s/5UILe7pSEP+ctC7ktvnyD1NhwWI5224lYedphMfFCLF0cKQbmNgIdWEP4gxCQrzm
         0CBXNSgsXuj7GgYVW+Twiw+i+BEN1MJokXGLAPKN90BA1/eCIzbnDx/bK4tkAhDHdcBs
         ackPebqBJyL+sMV2txJ0qKL4UuCuJcmrt3Y2xCkjdcVGFFuru1KUHMyGzYjaee/YgH3I
         5bRMJFBN+5EdtBDALMvVb1662W4beja8zaohpu0LFSnXqPgR4yZgEy7DnyIuEqoJJTWe
         gLid59QEfwgCpqLYe1ZdAYuhPFUCiejfIIbhYsy8CjbRDn8spMRqbgy5tnj7d9BzNlOF
         F80A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1710870744; x=1711475544;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=7NZdlDsf28pYdWfxYOgJXECtQ8Kh95rnKbeg37TkrSE=;
        b=Sk6HC/gx09pEGw9tAYvv9GRf203TpinwhD1f6WnwUUVGsYNlW9//gpSaOFkNR0DYDc
         U2IipnQxEvpqwyCcl23WDx5v0RvfqSW4jfprcAGMd2IVeP7MUjyXeD1ybLJ5cMgcsdem
         CzOLy7AmqEjpPRIDyno9eUXDUmtZ/Yko/u+sIMHH71beOa7FOT0Meh3/ODV81pdygJrY
         xEAfYd2xYapBREjMk0x8iG2hu44uGFfsJcHQRllWNi1cFIaVcTt6WPMW4WoqZlqHZ1EC
         GfkwMlgjhzxSf/sHOVe7HpW6VU/lvNrBK6w1v6776cgD0RKT3Qi6OaCnrTEAz43d3QjV
         u/8Q==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCWqJ61ytDLjxamSvliNGQPbsSqEMN9oA/5rle9MhYtGaXq5U0AtyuATDz313XBZmOkn0ram41+YRwWD3ntcm51b6gRx55rM5Q==
X-Gm-Message-State: AOJu0YxuJLyFwwEhHxZZOXEtImYGFTorm3M2isetxox1cr/rXfin6zXG
	tJzP2ShB/HtHmJABIQLeEWxKyomAHR9MBpm5h30YN7Yq2HkJL+FM
X-Google-Smtp-Source: AGHT+IF0nnPw3h1jeiZ6uHj2kXDN7T5F3svLOazGixr0lXCb0S89rX0A5N27Yzfuw/bH+NIeVmYLZA==
X-Received: by 2002:a2e:9653:0:b0:2d4:6c1c:7734 with SMTP id z19-20020a2e9653000000b002d46c1c7734mr10999318ljh.26.1710870742588;
        Tue, 19 Mar 2024 10:52:22 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a2e:b041:0:b0:2d3:3bc5:43ff with SMTP id d1-20020a2eb041000000b002d33bc543ffls341598ljl.0.-pod-prod-03-eu;
 Tue, 19 Mar 2024 10:52:20 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCU+alWv7xGv/ZbNxaS034doiS7LTc4itLapH2LnjEJq/v/bPc0U9bYWSFKP1i68w9qj3gms8EtXDn1Ophc4UOUPisssvkJJRq1yZQ==
X-Received: by 2002:a2e:904e:0:b0:2d6:84ee:f537 with SMTP id n14-20020a2e904e000000b002d684eef537mr1576312ljg.25.1710870740328;
        Tue, 19 Mar 2024 10:52:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1710870740; cv=none;
        d=google.com; s=arc-20160816;
        b=fNRG7dulG3LaFei6+GoKgaBA0MfB6m88G50ROpIFqjGmbnKd8w/2pmDLlXIzZpjTFT
         m0PhLaPmyJrkNhM0ivspSWhTAQYdl81phn+hb6pw+tFLYVYrobdeIZc4uWS54YScWLOb
         ksGk8QDY4rKtMBsI0nmV45jedgTuDjrV3oWZDuoZS+CoSwglC4deWhoNVmGmjD+3ECSC
         SiDgZK8mk1fSHTu5B9B7ANqGGy8cAnMzAT8H+NBEz5FIbRPm1d7HlcrZLNQ4OkOHTv0w
         OP3+5HjKA5L8uNDMwIPC0dcaNfuBv4lOplY0UCYZEwijT2JQVf0wNrHKnZ8yDy1ZNXOb
         35bQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=jsDdhGB1s86A5H2uDtk1GYBCObHAe8Bc+RYw8C3RVzY=;
        fh=SRw1Hrga+YCER1i7s8EZ7WeMGB3W3uXhYOqpEtjrTlA=;
        b=0O/hRNmhzJDUnomWxzGqjtGKQHEmA424d+A5w6c0MIqeavZrLLYNwN6qhYxUSltAFR
         3mRubmZjLH+O3vxovNNwD9h7bt2VtUQEjItxPISxikSVexvMMMMrrkQbucQt5uEmPdQb
         khfEMgyfR0CEyln9kzxf8UqB9hFf+dlSHXM4TDPHS5yDRkbapegoiyIP629IBnJNujrS
         KWR/lEq8lul9P+X6swIrn4GoB/EXtAbahhNHsebkhDFh4cXC1fGbZvGpXZ5tE4mdf5W5
         ogWm+mRzKYe5DkF6MvsE/Ej8xVzS8SkKan1abuLi9OMkSmOAO1wvcbQm2hYKxa5rCjxt
         LG/A==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@linux-foundation.org header.s=google header.b=MPP0cAyX;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
Received: from mail-ej1-x634.google.com (mail-ej1-x634.google.com. [2a00:1450:4864:20::634])
        by gmr-mx.google.com with ESMTPS id q9-20020a2e9149000000b002d449d21a98si694396ljg.1.2024.03.19.10.52.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 10:52:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of torvalds@linuxfoundation.org designates 2a00:1450:4864:20::634 as permitted sender) client-ip=2a00:1450:4864:20::634;
Received: by mail-ej1-x634.google.com with SMTP id a640c23a62f3a-a46dec5d00cso127667166b.0
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 10:52:20 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXNbEWDdGfRuYX6di19GLjk23nfhRgaNc8UuAsiumpnK6CvLZbuwbv5olKAc9qXbUbvAZbIrsc+LEpTrB6W3lKowDUN+qZ0YTchdw==
X-Received: by 2002:a17:906:2c48:b0:a46:8a9b:7fb9 with SMTP id f8-20020a1709062c4800b00a468a9b7fb9mr7850146ejh.51.1710870739529;
        Tue, 19 Mar 2024 10:52:19 -0700 (PDT)
Received: from mail-ej1-f53.google.com (mail-ej1-f53.google.com. [209.85.218.53])
        by smtp.gmail.com with ESMTPSA id w28-20020a170907271c00b00a46acfc72a2sm3748800ejk.84.2024.03.19.10.52.18
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 Mar 2024 10:52:19 -0700 (PDT)
Received: by mail-ej1-f53.google.com with SMTP id a640c23a62f3a-a466fc8fcccso711837966b.1
        for <kasan-dev@googlegroups.com>; Tue, 19 Mar 2024 10:52:18 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCXJ7Lr6sjwJppwJkM54WHD8zdi1XInKksoHNnVDlD7IN7p1uKkfq/CueM+48PVu2oBvP1x82yIoz7lALPaMHlySNYFiKT3dXWKLuQ==
X-Received: by 2002:a17:906:6d59:b0:a46:e595:f357 with SMTP id
 a25-20020a1709066d5900b00a46e595f357mr1437660ejt.9.1710870737954; Tue, 19 Mar
 2024 10:52:17 -0700 (PDT)
MIME-Version: 1.0
References: <20240319163656.2100766-1-glider@google.com> <20240319163656.2100766-2-glider@google.com>
In-Reply-To: <20240319163656.2100766-2-glider@google.com>
From: Linus Torvalds <torvalds@linux-foundation.org>
Date: Tue, 19 Mar 2024 10:52:01 -0700
X-Gmail-Original-Message-ID: <CAHk-=wh_L4gKHEo6JVZxTZ7Rppgz1b5pt2MJyJ2mZ-A8-Mp0Qg@mail.gmail.com>
Message-ID: <CAHk-=wh_L4gKHEo6JVZxTZ7Rppgz1b5pt2MJyJ2mZ-A8-Mp0Qg@mail.gmail.com>
Subject: Re: [PATCH v1 2/3] instrumented.h: add instrument_memcpy_before, instrument_memcpy_after
To: Alexander Potapenko <glider@google.com>
Cc: akpm@linux-foundation.org, linux-kernel@vger.kernel.org, 
	linux-mm@kvack.org, kasan-dev@googlegroups.com, tglx@linutronix.de, 
	x86@kernel.org, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: torvalds@linux-foundation.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@linux-foundation.org header.s=google header.b=MPP0cAyX;
       spf=pass (google.com: domain of torvalds@linuxfoundation.org designates
 2a00:1450:4864:20::634 as permitted sender) smtp.mailfrom=torvalds@linuxfoundation.org
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

On Tue, 19 Mar 2024 at 09:37, Alexander Potapenko <glider@google.com> wrote:
>
> +/**
> + * instrument_memcpy_after - add instrumentation before non-instrumented memcpy

Spot the cut-and-paste.

             Linus

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAHk-%3Dwh_L4gKHEo6JVZxTZ7Rppgz1b5pt2MJyJ2mZ-A8-Mp0Qg%40mail.gmail.com.
