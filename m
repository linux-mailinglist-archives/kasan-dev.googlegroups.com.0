Return-Path: <kasan-dev+bncBCQJP74GSUDRBUHX4COQMGQE3QWVZBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x13e.google.com (mail-il1-x13e.google.com [IPv6:2607:f8b0:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 314DE6602E7
	for <lists+kasan-dev@lfdr.de>; Fri,  6 Jan 2023 16:18:42 +0100 (CET)
Received: by mail-il1-x13e.google.com with SMTP id l13-20020a056e021c0d00b003034e24b866sf1273171ilh.22
        for <lists+kasan-dev@lfdr.de>; Fri, 06 Jan 2023 07:18:42 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1673018320; cv=pass;
        d=google.com; s=arc-20160816;
        b=kaexImTv7Q8pf4mLjd85LXGY3KdkF6D5wE8O4k7px21ni2SPMfVYfgZmUoPfZtPOfH
         gqw5u9X81RbLqxcIDMCvMZQLq5m1YF/a/+SOOYo48ru3vv3Kyfewl3hVjs+/enJRqGl7
         nvrapebH8imiQ45x5DM6wWrPv+DHzkSETcSfXUZh1UagBIZH6oK12Uo60sFpMU9FsvR6
         Eqp6a5O9GdUEseJdnu7/GNPvykbDrpeluNeJpg53ApFytSHRY57Q6uvRWPuZrprBJm+K
         MDliSr1tvlborN7Nd/AJE/vCbWG03Q2LCBjaa4hcQ0wFh2uOwPMMGY9CGSggK70jvQMY
         Gwxg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=2NkZdVuWwKP6OzA4MBLFcwgb0tXdgjOGyB3+S5II29s=;
        b=Xzo8hdoHy+IuE9w/mA3H7CjTffVPnkQ+JBSY7W+DqnryAAcJSFR3FOvqRiuXpoPRCg
         +NfDM56VqlCs732LcRMghb6UJKmgrTNYXNKRZyBdNJGeIHwrowgjz5lrgTrUZrCgK3jb
         P+g6Qd02ZXR0/IGgFBtHdSj6CjHMLiBYrK/BG0jSy3UuNiLim8bFuFNWAcqWzkaF6/dA
         YmxhLgqaCeeKGC1916L0x659FLmfWBq8jNWFsnIrKDAJm+RT3hTsgNhYkjKFpYDhBC9T
         rd1ghoAmXA2PDratlXcUzTL6nzhylN3pbAMFwVSJr6q7z2XR+/+tRCYomGOWkq8ntDoy
         9Xcw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.174 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:cc:to:subject:message-id:date:from:in-reply-to
         :references:mime-version:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2NkZdVuWwKP6OzA4MBLFcwgb0tXdgjOGyB3+S5II29s=;
        b=hxcSSjIiyvq1WCKw8D8EZI5lQxq8XTOI2lDqCng8UAXVQS1sGM+6CAxwP2NN6XSF+M
         BTF6EeOn6+PTiQvVAS/17ojdJAln+BHrGC1ydlk6qFQSc3F9O6VkR4kSkBnbYyDWFJ9R
         mc/ML4ZdBJIZnkyel4utYO3ryzY2UPk57zbr7vDeu3rW2r0XCXuIhSqh+9swUzMM2vIu
         4mlNz7KFL4v3gkDz48eO85m37G/+TZtDvCOHgVa5BX53LvYV4WkGeCvpKuUnwFh3uyGv
         4CDQl4BANo/qW6kC8qs4C3u0rJMCfdBrSgcyU/xsqh4mqpdVu3ZsilpQJHeNeQ50R+XB
         qwdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-gm-message-state:sender:from:to:cc:subject:date:message-id
         :reply-to;
        bh=2NkZdVuWwKP6OzA4MBLFcwgb0tXdgjOGyB3+S5II29s=;
        b=I+zLn59h1nyWVNZjR4Ia+dOy40nRZ2iJdpQWtcFAyxrTTurBTyy9T0SZe8TJtCGItv
         15rlrjtxneQIm6m91cWU3GnZSBXJ3nPFMX+mUSxIbi1Q/CfBfAHP41ghDMz1dU281Rxd
         7OGsK1M9nFEPQLL3FlSDGlzYreYW8iaj19TP5e5dg5Qjvc9sR5YODHqy0o8uDUoxEhUF
         3NubKfWo+BhjibQ2WnHiNJIabFcYkeZmH0+CtSR2oT3G/UKDuWyQrPzPUbub8QDEsxvC
         YnO7ECDCJL0rpCjCtJ9IvK7Exw9aJpI74b5BEyZ6wix17+lNxYeMDLwy4tYmpeNQtTNx
         9Ctw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AFqh2ko16mOC0Zr+/5k+r3DTnG/babYFe75c0oKggeo7vFLgleXBeoUc
	Dy1ZKdVFYNOZ6/MgeHVMJrk=
X-Google-Smtp-Source: AMrXdXvord5xUP9Lz7jAri21ZsNCh64uQzGJmTzn/o93ykOHCdIZy2d+OS5tmL52cSHeBLZmrElxPw==
X-Received: by 2002:a92:dc82:0:b0:303:24ea:c1e7 with SMTP id c2-20020a92dc82000000b0030324eac1e7mr4861239iln.162.1673018320776;
        Fri, 06 Jan 2023 07:18:40 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:54:b0:6de:9e24:a442 with SMTP id
 z20-20020a056602005400b006de9e24a442ls5462505ioz.9.-pod-prod-gmail; Fri, 06
 Jan 2023 07:18:40 -0800 (PST)
X-Received: by 2002:a5d:94cc:0:b0:702:9743:4858 with SMTP id y12-20020a5d94cc000000b0070297434858mr1271597ior.20.1673018320189;
        Fri, 06 Jan 2023 07:18:40 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1673018320; cv=none;
        d=google.com; s=arc-20160816;
        b=UIZ6nQR/dukZ7Ko7pg/4/NUnjJIcmlxbiGvNkvI7GP6jLqXcqaxOA6l7Ftm1u3O6S7
         UF9xjNjc4iLypNLPRa2rwT+M05sgx3PKT6NM0oa86b8J3Q8WDSs9NxJPA50WG0xVKXG+
         6COLgzFzLpFYzKqz59N93ZATLDFGUtbR7fSMApuaz48lMwH4D+6KItJmE4JB6XG17Yck
         r+4Xx/D2IP4wrzNWLyHGtD8/YDTdmGzt/OZSQ1mOQbl5HDcv6EqlsDoBsLAxlVFGXlJe
         2EFo7zYXh9nLhXnIivGOTLMRwgMRThqKwGdsR3svX83jni01NwuqcKwuqUasQkaOKZ4n
         g0Yw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=oLTT10Q08SvcCsbZuYubvWn2TjFc+1wP3y0ZN/T09Wc=;
        b=WIe3QalQmwtVFcA+hxQv67ZNNCZwwmdDclWewMV7EunowNv51/3uBd35MePNCMKmKw
         qXsSF/cxBEk8pSUqYkk/KFiFzRNRCatdSv5tEm36MFCgJL5iFs4eQQO4OlkroDFE3h37
         qcVKSLXIgvocTBVbMg3XUzsq45c/hmefdcm+TN+DKqPbCUZGHS63z5qRY7hB9cEmW5QR
         28cLm+Nkg6UKLX7+DafhxuHjNH7q5ub0wOOZPcNnjzmRYvnphDvFEqQk50XVWNdVDBfc
         k7BXhR+gXvFf8h7PXfmMstKSQMjhAMNK77SHdWpNa3UHVw278sTMx1GQykoTi8NljtTr
         y4tg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.174 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
Received: from mail-qt1-f174.google.com (mail-qt1-f174.google.com. [209.85.160.174])
        by gmr-mx.google.com with ESMTPS id bl12-20020a056602408c00b006e2d7e57bbfsi78549iob.1.2023.01.06.07.18.40
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Jan 2023 07:18:40 -0800 (PST)
Received-SPF: pass (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.174 as permitted sender) client-ip=209.85.160.174;
Received: by mail-qt1-f174.google.com with SMTP id a16so2198633qtw.10
        for <kasan-dev@googlegroups.com>; Fri, 06 Jan 2023 07:18:40 -0800 (PST)
X-Received: by 2002:ac8:7778:0:b0:3ab:af31:ee3e with SMTP id h24-20020ac87778000000b003abaf31ee3emr28246270qtu.60.1673018319339;
        Fri, 06 Jan 2023 07:18:39 -0800 (PST)
Received: from mail-yw1-f180.google.com (mail-yw1-f180.google.com. [209.85.128.180])
        by smtp.gmail.com with ESMTPSA id q8-20020ac87348000000b003a8163c1c96sm621072qtp.14.2023.01.06.07.18.38
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 06 Jan 2023 07:18:39 -0800 (PST)
Received: by mail-yw1-f180.google.com with SMTP id 00721157ae682-4a263c4ddbaso27160077b3.0
        for <kasan-dev@googlegroups.com>; Fri, 06 Jan 2023 07:18:38 -0800 (PST)
X-Received: by 2002:a81:17ca:0:b0:46f:bd6:957d with SMTP id
 193-20020a8117ca000000b0046f0bd6957dmr4281773ywx.383.1673018318622; Fri, 06
 Jan 2023 07:18:38 -0800 (PST)
MIME-Version: 1.0
References: <CAHk-=wgf929uGOVpiWALPyC7pv_9KbwB2EAvQ3C4woshZZ5zqQ@mail.gmail.com>
 <20221227082932.798359-1-geert@linux-m68k.org> <alpine.DEB.2.22.394.2212270933530.311423@ramsan.of.borg>
 <c05bee5d-0d69-289b-fe4b-98f4cd31a4f5@physik.fu-berlin.de> <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
In-Reply-To: <CAMuHMdXNJveXHeS=g-aHbnxtyACxq1wCeaTg8LbpYqJTCqk86g@mail.gmail.com>
From: Geert Uytterhoeven <geert@linux-m68k.org>
Date: Fri, 6 Jan 2023 16:18:27 +0100
X-Gmail-Original-Message-ID: <CAMuHMdU8AKSdujbr=nwaBUy4q4z_R=MERnb5CBPPv=A63BVFXA@mail.gmail.com>
Message-ID: <CAMuHMdU8AKSdujbr=nwaBUy4q4z_R=MERnb5CBPPv=A63BVFXA@mail.gmail.com>
Subject: Re: Build regressions/improvements in v6.2-rc1
To: John Paul Adrian Glaubitz <glaubitz@physik.fu-berlin.de>
Cc: linux-kernel@vger.kernel.org, amd-gfx@lists.freedesktop.org, 
	linux-arm-kernel@lists.infradead.org, linux-media@vger.kernel.org, 
	linux-wireless@vger.kernel.org, linux-mips@vger.kernel.org, 
	linux-sh@vger.kernel.org, linux-f2fs-devel@lists.sourceforge.net, 
	linuxppc-dev@lists.ozlabs.org, kasan-dev@googlegroups.com, 
	linux-xtensa@linux-xtensa.org
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: geert@linux-m68k.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of geert.uytterhoeven@gmail.com designates 209.85.160.174
 as permitted sender) smtp.mailfrom=geert.uytterhoeven@gmail.com
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

On Fri, Jan 6, 2023 at 4:17 PM Geert Uytterhoeven <geert@linux-m68k.org> wrote:
>
> Hi John,

Bummer, "Hi Adrian", ofc ;-)

Gr{oetje,eeting}s,

                        Geert

--
Geert Uytterhoeven -- There's lots of Linux beyond ia32 -- geert@linux-m68k.org

In personal conversations with technical people, I call myself a hacker. But
when I'm talking to journalists I just say "programmer" or something like that.
                                -- Linus Torvalds

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAMuHMdU8AKSdujbr%3DnwaBUy4q4z_R%3DMERnb5CBPPv%3DA63BVFXA%40mail.gmail.com.
