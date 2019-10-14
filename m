Return-Path: <kasan-dev+bncBCMIZB7QWENRBF7JSDWQKGQENKRPQYY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73c.google.com (mail-qk1-x73c.google.com [IPv6:2607:f8b0:4864:20::73c])
	by mail.lfdr.de (Postfix) with ESMTPS id DC70ED5DAE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 10:40:56 +0200 (CEST)
Received: by mail-qk1-x73c.google.com with SMTP id g65sf16319621qkf.19
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 01:40:56 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571042455; cv=pass;
        d=google.com; s=arc-20160816;
        b=jQqn9Ul1VM69zo6OKdglfw1d9QvHN6Ow1tHMC2VpWl4NDQoPUqoGOxrKVxn5bCGI53
         A2TdvmxMDlcLokmP4JRF1luCHxExCGbs0mi1R7Gzx2BgFSSnfFlmpkyP9gxWPnA3e83+
         D5LKa6YjIBBuxSggQDwaUmLIHl/2NmMIfHAkGeIeWqoXwqWa4U+KhIOtZCO+AYrLCUQR
         ZFAWBvBbzA1ThrRnuFq+8WRcrQ8reurcU1ovVD2h+T2wqu5PDn28/dOtmHQIOZGu9S2M
         8budPOU8XYF1Y4mfKzw3kJYISXigDi9MVMQaMfVmV6L1yFtsTJkbSpdr994QN1iOYhTZ
         gHmw==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :to:subject:message-id:date:from:in-reply-to:references:mime-version
         :dkim-signature;
        bh=gJduDdUykFTYcmOo2SgSFwdTq5fkXWLrP/0LCIM3YAo=;
        b=tOQZx6AHWPbEhyGgjsrCY/WcBXGxZkeQkUMRZACnHhBICTwIx6QMATOzgfbw5Osm9t
         luj7Cr/1mFWLr/PWDNLlAoOrqllmHi0sGwY8SeROTRmLULsdl3sX1rSlBTuqnOuuKdLK
         X8Gn9dGp48ld3nKXUTlkr31ca69nkLd1YE/U7BuTFfYtvddceapsClMmCEiz3snswr3J
         rdAsZOjRQs+icwtnv2fDMRBNviOdFUEadQLhVhL+iruMjM060S6ouZpJR52DSNND2j/8
         +4lQzlqThnU9j4vAKfYDJggvriirC/HiZkeByhAF+aAKkLqHn8EzIHgAaUlNHPDT7Tbm
         nPRg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Th5jluCN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=gJduDdUykFTYcmOo2SgSFwdTq5fkXWLrP/0LCIM3YAo=;
        b=UHSc1q+A0Ae5Di6xj6YhRrHjDNyxR2M4oAfxAuXrr2O3GYJJPW2CTjuU64KVtYTgPK
         LfF9sbbzOeMxkfers34K7Z0cS9qGUUwqn9t03cXQTMCSDB6lBeivpjRIXWyPt+mkfOlh
         etmwJ9SM7k9Qh4T5ZypE9RGf+8ITrRV14u61qqg1GW9HTO/S/LlVLBdaW9gABizLukLp
         t8HSKIsWZqvz4C2bYBa0dzj+1Fq7ucgRfUjUTYEMh+euja1aHggHW6bcdz37u/Ng49hF
         IwkBov1qgby3MPIbjY+gSTCjAyPKCd41QeiI9pJ8CSSZoVCraQhLbNGlhuZIDqWZP7l2
         uaeA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=gJduDdUykFTYcmOo2SgSFwdTq5fkXWLrP/0LCIM3YAo=;
        b=SAhmWbS9VeKXqBo/h5YliGRBTOz8LJSs+JA8uMrXFdPJmG30JSwghET4EfqlsRCOtn
         SEmZY36Pjk1sP/bY5xVMyN1Y50M6fPl+AsfPBihKWyBdxOsWPLgFi38uspvt1V2/QWnB
         fpT3K4cim+KhOvn3+xA6RtK82UNqyQp+w1T1DoGMk19flxfJWlZLE0rHDI3mcphbAevt
         VcHtwj7GUi57/5CUO/mZ3B41BLBud8RbG95PHwCQKRDemEUyB/M8Oaji61QPiBL+zo+i
         IQseSDEB/a90fygo2qBm5U56Id3M+f2mXKgsbVvpC0GDCHFrj55T54LMxORh2LUKIUkV
         aTjA==
X-Gm-Message-State: APjAAAUbJLBhbT7Pm0zD71KkfHJWlZSYJKnKavMa3ChadWozi5/25Q96
	2wLKJi4BsCLB3nOzOBUyjqI=
X-Google-Smtp-Source: APXvYqwUYaZ88OJQbuKsaB6NNHs7vjb2k7vMtHoRzg5pVJzhCO0/wL+Usk97Ktb29g1WpFYGtrg0xw==
X-Received: by 2002:ac8:2a38:: with SMTP id k53mr31975116qtk.387.1571042455778;
        Mon, 14 Oct 2019 01:40:55 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:927b:: with SMTP id 56ls2458198qvz.2.gmail; Mon, 14 Oct
 2019 01:40:55 -0700 (PDT)
X-Received: by 2002:a0c:c70a:: with SMTP id w10mr30053064qvi.218.1571042455468;
        Mon, 14 Oct 2019 01:40:55 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571042455; cv=none;
        d=google.com; s=arc-20160816;
        b=X/Hz6N1/szgDymyVxp8jI8jTE0sZSGShEoPQoub28HurJLbVdhndf+54giw2T10//k
         XfrzEleQu/qE8u52e3HXIVVbm7omOLMwn5UDHOuatggWpnN1k4hPqq8pJF89GSMC6eBr
         pO8epCx5ht/ro77so0yVoVZ7D/5H4xzftkyRbKgQOhOSwXnwG/wBnjBRtWtbouEQ76hA
         cRVe6x50zP0Q5Gp3sWFVIsKS3Q1IKZmufGZzm7g/6UvvrZeKwa1ml539s5besaeaF9aY
         A/vd4TIOFOQ5LZTOmhBuircTAzhcSrMNYUJJ2toDq0jSRFw3qrfRs8ZdB7o0ECr+k2ny
         usCg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=IhvMgu+8NRfvEZVb3Yd23S2a/QiDqpj2U4nfhQK8p70=;
        b=X24j2m9kmOsktzKEHZUfh0KQhkhzU/hoVJ21ob1dkGqbkuTNdUU21YexZOLuCR7ubN
         N5Vt68IBQtUBrAKKjTWImZSqle+E+dxa3lQo1oyIFOLobowGJ+diN8ooYc9GSrfFh9JH
         9cQfc8PoOag+MUcVeYt2PHK78CQmC9t/ocKyZF4xXgeC53v8JsULS0CqVcWKhCPyEcCu
         M/fA73zwzl8+K71e/o0Wx3EmQQOTi+mUlq6pWyUiHM0D6g6boJF0CRdWtVqeySQTQQhr
         7PfgLfbKx6grYoniX022DFuytimJ30+1Qa/vhhHRJ8uY3uoh1eiDdFjK5xd+eT05fcoe
         lAEQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=Th5jluCN;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id o8si526988qtk.0.2019.10.14.01.40.55
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 01:40:55 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id x134so15196569qkb.0
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 01:40:55 -0700 (PDT)
X-Received: by 2002:a05:620a:6b6:: with SMTP id i22mr27778578qkh.256.1571042454774;
 Mon, 14 Oct 2019 01:40:54 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
In-Reply-To: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 10:40:43 +0200
Message-ID: <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: sgrover@codeaurora.org, Marco Elver <elver@google.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, LKML <linux-kernel@vger.kernel.org>, 
	"Paul E. McKenney" <paulmck@linux.ibm.com>, Will Deacon <willdeacon@google.com>, 
	Andrea Parri <parri.andrea@gmail.com>, Alan Stern <stern@rowland.harvard.edu>, 
	Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=Th5jluCN;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
 as permitted sender) smtp.mailfrom=dvyukov@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Dmitry Vyukov <dvyukov@google.com>
Reply-To: Dmitry Vyukov <dvyukov@google.com>
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

On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
>
> Hi Dmitry,
>
> I am from Qualcomm Linux Security Team, just going through KCSAN and foun=
d that there was a thread for arm64 support (https://lkml.org/lkml/2019/9/2=
0/804).
>
> Can you please tell me if KCSAN is supported on ARM64 now? Can I just reb=
ase the KCSAN branch on top of our let=E2=80=99s say android mainline kerne=
l, enable the config and run syzkaller on that for finding race conditions?
>
> It would be very helpful if you reply, we want to setup this for finding =
issues on our proprietary modules that are not part of kernel mainline.
>
> Regards,
>
> Sachin Grover

+more people re KCSAN on ARM64

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CACT4Y%2BaAicvQ1FYyOVbhJy62F4U6R_PXr%2BmyNghFh8PZixfYLQ%40mail.gm=
ail.com.
