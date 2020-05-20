Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXFLSL3AKGQEZVKIXPA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id B39F61DA7F6
	for <lists+kasan-dev@lfdr.de>; Wed, 20 May 2020 04:28:45 +0200 (CEST)
Received: by mail-il1-x138.google.com with SMTP id v14sf1426938ilm.10
        for <lists+kasan-dev@lfdr.de>; Tue, 19 May 2020 19:28:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1589941724; cv=pass;
        d=google.com; s=arc-20160816;
        b=IgLt0gsWLmzT+j909KDpdGLXtpn4OQQDNfXY1Uhy1ADN0EBNT5N3DPEstxWsKGFmKA
         fMG+r/38ffU10IcLKRqBXi0X2mgWBa0X95nC0zILHiyHC4ziZfykaod7bQ9k4ozKHzYZ
         syQkebuoCnqVOXHdGnuDfUwFuXH0TkOAkxln3oilsv5PoxHTt9Z98bo1bEZPHCHmdV4v
         WApF/Lf2fbgaU9m5jOCR1SdXvdrtd5HEh/DLFR984DRUDYqiBLjjUt9wnoUpjXF9Iaje
         Jndgb+5bv16Yw3QAEgZSJDYsYjebW41VbYHcpYLxnkdUsjeGR/+QxZF/61F+dXv679JV
         m6Ug==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:content-transfer-encoding
         :sender:dkim-signature;
        bh=Tt5ydKF38jzrduZxJu7mE0rKY/XIfN0jqMkQlGKp/GY=;
        b=brEmJanIpa6MlG/IR18YMBhPn55i7tTGZpRRSp8S6VArWq82ZWVACsf13Ob3jjt3Pd
         SneVaTQoUayDroSqbjN31tf8GHmXF83+j3cIZ9DPCJIr+bGwCBBxT/Q+TY04iR7MKjiQ
         dRKzfrG4WpqdiIRsa3sx7NIbffOaThXoBSoigPpgzZ/rwMFyhRPyBWtw1rkQzYS8wKLG
         faHsMLWvLDLa/LdiKRvVbjI7MovurJ5lBXU7MAGQuI5WXKEDjLMWPCneKjs6PtwgbQAF
         Dyyeat2CcOUbD8lthfX1HEFSUQNO4o0QI8FLC3nf1hkDuMRbhwqpWxpl3BZ0ILGoDui3
         e7IA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=cQpNRMs3;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:content-transfer-encoding:from:mime-version:subject:date
         :message-id:references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=Tt5ydKF38jzrduZxJu7mE0rKY/XIfN0jqMkQlGKp/GY=;
        b=CR9yXgYNpAxmpfNvh8abZtMtLa+VmBpUm4j5MJ+hQclnvsmyO/TIBC8KesAEYOWZfI
         wQ4wTnxVpnki31cZIOPllS+8EdSoVWwN+INSZwzdR6ksDMI/axIp5JJNGsVh5EeRmW2y
         lN4H8iLZMZLjW/ANcHVoD33JyG0pzR+p99GU+ig3K2jhguU7bZqNE5FLlWN3L+0W15y/
         Sgr2sDWTSfecPvsSZntj1c7gSMXtdGIMBuLR8h0SdV2kTWzo9VQ0EpUDgMK+JGerxUeH
         6D6nwSqjpwZmMNNxfcoaU0hCflDmN+BdeiRXtz2M5BckFvradaRrkM2ufDNcx6ek+uqW
         gN1g==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:content-transfer-encoding:from
         :mime-version:subject:date:message-id:references:cc:in-reply-to:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=Tt5ydKF38jzrduZxJu7mE0rKY/XIfN0jqMkQlGKp/GY=;
        b=uQR2VUQRpmMuzx4owLfq00lqeD3N3ebfmhpF3TXOdXNZswfGn4a3A+vK6fSMzKlElc
         +YV/DEJDIlfTGvyTOUhYGqcqHaDfdYFUirYRfDwUTi41nKpLWrRtpHiYx59Pe2OJ0FAY
         +OSMh7O344IduGH1v4QVUNUU6FqGuDOA8+bJDpVwaJebIkHqtmCp2YlLGBXOrfcCVRgk
         zCwEfnkz0gLGFAcVgT3gElSbEndVEaDNTqsiXFcTZUyrrgsDwF46K4nBSwEzRi6Re495
         VGK3F3ZfVVsAbuSCup7Uy0+juLenSTUfEdGFqWSi7OUBoZvqgxURfQcfCKwXufK11wtA
         DJxg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM5333SHcbQsf6RfF5sYE+wNfWQbdu41Ru2OHRSQgM99zP26TWsIfb
	8TWjSXc0Ksmp6hoDwFCxZ6A=
X-Google-Smtp-Source: ABdhPJxEOPjF68HcHtnnTBGz82pNlBvWhlxE/pPDVaz4l6ZkESAhePdrMlHNFYvsVFyjOzaQydjDZw==
X-Received: by 2002:a05:6e02:589:: with SMTP id c9mr1981129ils.271.1589941724637;
        Tue, 19 May 2020 19:28:44 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:9a98:: with SMTP id c24ls364820ill.0.gmail; Tue, 19 May
 2020 19:28:44 -0700 (PDT)
X-Received: by 2002:a92:af44:: with SMTP id n65mr1863569ili.61.1589941724274;
        Tue, 19 May 2020 19:28:44 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1589941724; cv=none;
        d=google.com; s=arc-20160816;
        b=GVFM2znKB2s4epNDNeglFabgnICyL7uIYVBrffB4qb5nGuT7Opju8NkBpRmmdV1lMv
         y1+AwyRL2s3FKAMVRpidkAKR0uj7lv4iNml2vZNZ85z67RTmqkDkGFIlKDVKfItwDOFZ
         jIhyWUHMaeerm8bhZclKiENYk0/gF1oBi75YSvtIfVAUs8Qdo3vQGwq6NMnYHyoBSjUs
         WKn8z/8N2t+pHyKHkDlAm2tsUiGoU1oTULdWAgS3FXf/FHUFxMFw87avi8zjV3Vi6brG
         svY6+Ec/RvO5epd+wwKdJ6XfGK+HCma20pRSJaLLZx/TVDalsDQraQP8GjfkFydTwYFI
         /vlg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=6Y7HJEX97OtUoScp+6aHU6PvBtaRCji4KFMDWzl/1dU=;
        b=o/xaATJshv6YSBTdGKK/K8+natQzleQP4E9YkR5hB6LH+cL63hpMkaQyi4iYLAgKsr
         6LTH9wnW9JvXVEQXa3LaMirEeu5oVEfH5Wc8ZhPmCrFMXHbFsAOHCwnG4ngXa407kFge
         5+eVhHMfOGzMCyn1PgIJvSl9ItkKdU4iMmNK2EW4sERBwIzcppW7tjre2Hb6paYMwUMe
         nqNx+LDx7yv7fMtoHmhoMqHez8bll8yuM0I3uJ0bjgL1olxX1x91lMSpwyyDjBQ9bBPZ
         ccTz/4RaQm2CmYTkzhJXAn8hA/tvuOjm94ubDKoHb9jITzFW597Uj8R7OjKkD5Rq7hmV
         VxSQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=cQpNRMs3;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qv1-xf42.google.com (mail-qv1-xf42.google.com. [2607:f8b0:4864:20::f42])
        by gmr-mx.google.com with ESMTPS id b11si70606ilf.4.2020.05.19.19.28.44
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 19:28:44 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as permitted sender) client-ip=2607:f8b0:4864:20::f42;
Received: by mail-qv1-xf42.google.com with SMTP id z5so671176qvw.4
        for <kasan-dev@googlegroups.com>; Tue, 19 May 2020 19:28:44 -0700 (PDT)
X-Received: by 2002:a05:6214:1c2:: with SMTP id c2mr2800690qvt.185.1589941723237;
        Tue, 19 May 2020 19:28:43 -0700 (PDT)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id y66sm988332qka.24.2020.05.19.19.28.42
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 19 May 2020 19:28:42 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH] READ_ONCE, WRITE_ONCE, kcsan: Perform checks in __*_ONCE variants
Date: Tue, 19 May 2020 22:28:41 -0400
Message-Id: <360AFD09-27EC-4133-A5E3-149B8C0C4232@lca.pw>
References: <87y2pn60ob.fsf@nanos.tec.linutronix.de>
Cc: Marco Elver <elver@google.com>, Peter Zijlstra <peterz@infradead.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>, Will Deacon <will@kernel.org>,
 "Paul E . McKenney" <paulmck@kernel.org>, Ingo Molnar <mingo@kernel.org>
In-Reply-To: <87y2pn60ob.fsf@nanos.tec.linutronix.de>
To: Thomas Gleixner <tglx@linutronix.de>
X-Mailer: iPhone Mail (17E262)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=cQpNRMs3;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::f42 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On May 19, 2020, at 6:05 PM, Thomas Gleixner <tglx@linutronix.de> wrote:
>=20
> Yes, it's unfortunate, but we have to stop making major concessions just
> because tools are not up to the task.
>=20
> We've done that way too much in the past and this particular problem
> clearly demonstrates that there are limits.
>=20
> Making brand new technology depend on sane tools is not asked too
> much. And yes, it's inconvenient, but all of us have to build tools
> every now and then to get our job done. It's not the end of the world.
>=20
> Building clang is trivial enough and pointing the make to the right
> compiler is not rocket science either.

Yes, it all make sense from that angle. On the other hand, I want to be foc=
us on kernel rather than compilers by using a stable and rocket-solid versi=
on. Not mentioned the time lost by compiling and properly manage my own too=
lchain in an automated environment, using such new version of compilers mea=
ns that I have to inevitably deal with compiler bugs occasionally. Anyway, =
it is just some other more bugs I have to deal with, and I don=E2=80=99t ha=
ve a better solution to offer right now.

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/360AFD09-27EC-4133-A5E3-149B8C0C4232%40lca.pw.
