Return-Path: <kasan-dev+bncBCXKTJ63SAARBFVFUGZQMGQEHNDAAFQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 68D4B903D88
	for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 15:35:20 +0200 (CEST)
Received: by mail-pj1-x103c.google.com with SMTP id 98e67ed59e1d1-2c2d4ea53c7sf2717754a91.1
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Jun 2024 06:35:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1718112919; cv=pass;
        d=google.com; s=arc-20160816;
        b=ET6sBZDGooucsZcSX/33tGViKVmKhEDlOYSETD60Lcejsmy+tichlkEo4w0dudkZ3f
         /6jBIk8ddP09V9bq36mSjK5fAagp8da21ghPtLQnwbcbxBvSmIdjkY/ypGPwEMm14SRS
         4oXLBRAV03S18OV6WU1fHcujAR9lsGJP6NYs7jX9OGKuOWWQlprIjlC0gm5zPw//PSt+
         RK8G+ticY2tAqmoLtjv60hjoZKlbU/6szks/Br0FrJULtFj+fYLUsk9uzXq+jgu2ydo1
         K2FiMrfdLd98NEUtFS10itlEKmM9kf11sNPSKNXn7yn46ZRDIjjH0ynRLsfmlNK5RJ/R
         KdEA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RrHSN4DtV5tfuNdnR9QBByDFLv7W9n67w8uy2Kkhz6Y=;
        fh=fZiYuDIKtFZG2TPXmISvNCNQVo9jySeMDbGr/keFuY0=;
        b=J7ka/KMGgKUKp+Rd7/pID5GtBk9P+iFi4ur9GzvKgLvys0+T4o3vdzAHxdtz7KwHBF
         sYnEmP37FMThbYJnoLFOCnhB2q7+Wr8BitZ70WE4vXCq8lHfa7JIYjrp1nXw9Dha5pLv
         nolxeIGnA3LhrHmUO5n76qQ+a2+0JJHXsgEXDiIrraS9mkZ4wSOaOWcBpZ0E8D9S3VKo
         bo0D4ZXFpH/MkeA4X2DlOCpdItS+VvCdYbuysPUXVLtLA/khwOhB9YSfr3oMTXmyt+cm
         2FTIbFvlGhl7/CuOK8hT7r0vVoM4fMFdQIgYfczEY4hA21utFq2iBQqslp5W/Wkpivve
         XtBg==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kfz0qFzK;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1718112919; x=1718717719; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:from:to:cc:subject:date
         :message-id:reply-to;
        bh=RrHSN4DtV5tfuNdnR9QBByDFLv7W9n67w8uy2Kkhz6Y=;
        b=firkzWBe3pjMNOifCipR/0PQexWpZ5jJozXWa/wTNFRQS7jwFPgVBlg05XSLljURGQ
         f5Ez/vAzp2M0PPYBTl64XjmMr7PIZO+17Y+Xqgyew6q5vrscyC7j9wnGcOaWBHtHsKzk
         tIsc26hlp0lxV5Bi0QqRo1SlN9n95UZ9PkrjJ6HzaBIQU4IlbDAF2OLPd3575bs83esu
         /mjCeAttuiQkka5y3lb8c2keJuv9fg7j12Mi+L5oesXdhvhJ48ckIEIrKU/eQnYvyYsg
         4YD5M6z0LjXeDYW5vxkXCUZg/Xme9xOLpRB+DTfP7Pv4y3hX98b6mk6NVyBGOSa5Gpnw
         cdjA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1718112919; x=1718717719;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :from:to:cc:subject:date:message-id:reply-to;
        bh=RrHSN4DtV5tfuNdnR9QBByDFLv7W9n67w8uy2Kkhz6Y=;
        b=iSo4G8EseEyYtkmrSUxWKcsp+TPU7om9x41zlIUGLalCeHatJN1Q7WswBjIRHlTryN
         T0zZtrvOba+Z7zZctmVA2A0UeiDcpzULsWQIVCvDDouj++H439p9gwaEGudzlJGMKEiL
         iXmYrL84/FzDvmJ0TYvL5LGS2aQDt3RvMqP493+8ADwKbP21EewBwn4kFK73QBglRkr3
         C68U1zx9ePhLFE949sncOZAC+Zt6G6rOvc/S+Spq9M/4D9xj8VFBSicJuDYsvZMxIG2V
         MiYrIOQz9Be5xzsHEDnE/H63chlpz3A8dU2OlAVSm+u2SC3+m7FmYodhRyNkfkxHpgB+
         5l5g==
X-Forwarded-Encrypted: i=2; AJvYcCXxbLOcMgRvioZ0DuIUJwp06ZpDYBYa3YHBjzj7DDqDdfVCBK/tltV51jM6+aR9q1Fi+yPFLur5tg2HHfIEy4Wl7jkpIReZHw==
X-Gm-Message-State: AOJu0YxM+t7YX1bLmoV2o1dQsxSN+swOLABrMP9sQzrvChXX4e2oYc9g
	htkGwcw1pSXENEpE3ZrDDLHe0WTEaOpaFvi6E7XEIzsiOiib8Hl+
X-Google-Smtp-Source: AGHT+IHYOkLEjg5sKSF9GVgObCvfPbWgWjpWB345qjAjuFFeMy3YtXXoWagbIrlp/RzU0vyRMEgaXg==
X-Received: by 2002:a17:90b:3701:b0:2c2:d66d:1b8c with SMTP id 98e67ed59e1d1-2c32b4e55bdmr3589148a91.20.1718112918883;
        Tue, 11 Jun 2024 06:35:18 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:5402:b0:2c2:4109:9444 with SMTP id
 98e67ed59e1d1-2c295e99171ls526223a91.1.-pod-prod-00-us-canary; Tue, 11 Jun
 2024 06:35:17 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCXWqoGDxA94G11Fldj58i5jIGrwZl4ynW2uncjGkFqQwbMXATd0DzEE3+igt/SQAMnG/z6xSd+RnTLFmBabeLH32ta0MRf9x5rmhA==
X-Received: by 2002:a05:6a20:9c8b:b0:1a7:9b0e:ded3 with SMTP id adf61e73a8af0-1b86bc161dcmr3486668637.11.1718112917646;
        Tue, 11 Jun 2024 06:35:17 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1718112917; cv=none;
        d=google.com; s=arc-20160816;
        b=oUixjzhdc8GIA9vV5/OYkWnlwqvLoA3xo87lUuuYya33Yp6rlQ/21nOqQSoYOlLdEN
         6Mq1fsTLolvcUB9fdaRe9WRK5C0B3Hx4ElUJ0ikI5H8TwLifZWbWwDcpD97B4sXTVAti
         PMWxYrgH4PT4L8TNs8kwfTAupIhO2yvEpy6gYfIBEbJFOSR7CBaNXHyCk1IJcJvD3a5w
         Ep7gBs8XQg0hpjZh2wcbUj6IkNHxTsVgl9D9alhIu98PbTlDQ4yGsrvklctezuyxKN10
         1esbTSb/v7lw5G3/yYxZCsA0vyH+3AeKzkY125qJhvSXBDfiPmxI0gvQQmDDmuO8qhc0
         vNsw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=3oHoG/rUvG+suNrPba6sWXwasYJyuMVroRrTP18iosU=;
        fh=LtnBKS7UuMUa2AkxXEI/p5EXaMtDlWNbswObp1k2blU=;
        b=y2j9sNaHY6QSkDudEcO/s/7RfMCLzSVt7RmttPnr6s/QDwKDl/zvslz9HlZggCMoMc
         jlNRHc8Mv5lG0rhHuhtBLQHD8CI8TyTjPJCaf7yLupw21xgdKVwvqu/6hpwYLk3heBmx
         FCZRSZHqN7yXWzLGqfLmIQFjWGH05eRZQfTS889goyYfyG/8Dw4qu4IrOO2OQXtUoCBe
         lLQfcnfip+ywhG6tcCARCxuiANTVuOudFXWrv3I6ae8ozvIg/NfSbUE06xAJ4FFUDACb
         gS1ui6Bdez3rPOo5AN+3b++QtJVK3rkWc7XyPgin1Y9YbRrth7VKSB/Kc86biBnAtC4L
         EvVA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=kfz0qFzK;
       spf=pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62b as permitted sender) smtp.mailfrom=nogikh@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pl1-x62b.google.com (mail-pl1-x62b.google.com. [2607:f8b0:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id d2e1a72fcca58-70476b1f1e1si241732b3a.1.2024.06.11.06.35.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Jun 2024 06:35:17 -0700 (PDT)
Received-SPF: pass (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62b as permitted sender) client-ip=2607:f8b0:4864:20::62b;
Received: by mail-pl1-x62b.google.com with SMTP id d9443c01a7336-1f70ec6ff8bso169355ad.0
        for <kasan-dev@googlegroups.com>; Tue, 11 Jun 2024 06:35:17 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWIpgpGjQLB8Nkizlw0IAI0vQ9mUVtQWC3feg9Yv6BNOr8ybRJqcKFt2p5FuN4dXuqo8XrJXl007O51Ogz1no61o9blX4PdYizJvg==
X-Received: by 2002:a17:902:f646:b0:1f6:262c:6750 with SMTP id
 d9443c01a7336-1f72ab8fa78mr3268835ad.0.1718112916889; Tue, 11 Jun 2024
 06:35:16 -0700 (PDT)
MIME-Version: 1.0
References: <20240520205856.162910-1-andrey.konovalov@linux.dev>
 <CACT4Y+bO03Efd48XW7V6F2D9FMUoWytV8L9BL8OK2DR8scJgmQ@mail.gmail.com> <CA+fCnZcd2nJ6XLmJcPfwVJf9wUcHqWjYnafDdV8pmm3HpjY7Wg@mail.gmail.com>
In-Reply-To: <CA+fCnZcd2nJ6XLmJcPfwVJf9wUcHqWjYnafDdV8pmm3HpjY7Wg@mail.gmail.com>
From: "'Aleksandr Nogikh' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 11 Jun 2024 15:35:05 +0200
Message-ID: <CANp29Y4ds327opXYv0VXyfZ0fT4srDjO5r9Y6grDZigARFfWaA@mail.gmail.com>
Subject: Re: [PATCH] kcov, usb: disable interrupts in kcov_remote_start_usb_softirq
To: Andrey Konovalov <andreyknvl@gmail.com>
Cc: Dmitry Vyukov <dvyukov@google.com>, andrey.konovalov@linux.dev, 
	Alan Stern <stern@rowland.harvard.edu>, Greg Kroah-Hartman <gregkh@linuxfoundation.org>, 
	Marco Elver <elver@google.com>, Alexander Potapenko <glider@google.com>, kasan-dev@googlegroups.com, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, Tejun Heo <tj@kernel.org>, 
	linux-usb@vger.kernel.org, linux-kernel@vger.kernel.org
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: nogikh@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=kfz0qFzK;       spf=pass
 (google.com: domain of nogikh@google.com designates 2607:f8b0:4864:20::62b as
 permitted sender) smtp.mailfrom=nogikh@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Aleksandr Nogikh <nogikh@google.com>
Reply-To: Aleksandr Nogikh <nogikh@google.com>
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

On Tue, May 21, 2024 at 10:46=E2=80=AFPM Andrey Konovalov <andreyknvl@gmail=
.com> wrote:
>
> On Tue, May 21, 2024 at 6:35=E2=80=AFAM Dmitry Vyukov <dvyukov@google.com=
> wrote:
> >
> > On Mon, 20 May 2024 at 22:59, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@gmail.com>
> > >
> > > After commit 8fea0c8fda30 ("usb: core: hcd: Convert from tasklet to B=
H
> > > workqueue"), usb_giveback_urb_bh() runs in the BH workqueue with
> > > interrupts enabled.
> > >
> > > Thus, the remote coverage collection section in usb_giveback_urb_bh()=
->
> > > __usb_hcd_giveback_urb() might be interrupted, and the interrupt hand=
ler
> > > might invoke __usb_hcd_giveback_urb() again.
> > >
> > > This breaks KCOV, as it does not support nested remote coverage colle=
ction
> > > sections within the same context (neither in task nor in softirq).
> > >
> > > Update kcov_remote_start/stop_usb_softirq() to disable interrupts for=
 the
> > > duration of the coverage collection section to avoid nested sections =
in
> > > the softirq context (in addition to such in the task context, which a=
re
> > > already handled).
> >
> > Besides the issue pointed by the test robot:
> >
> > Acked-by: Dmitry Vyukov <dvyukov@google.com>
> >
> > Thanks for fixing this.
>
> Thanks for the ack!
>
> > This section of code does not rely on reentrancy, right? E.g. one
> > callback won't wait for completion of another callback?
>
> I think all should be good. Before the BH workqueue change, the code
> ran with interrupts disabled.
>
> > At some point we started seeing lots of "remote cover enable write
> > trace failed (errno 17)" errors while running syzkaller. Can these
> > errors be caused by this issue?
>
> This looks like a different issue. I also noticed this when I tried
> running a log with a bunch of USB programs via syz-execprog. Not sure
> why this happens, but I still see it with this patch applied.

For the record:
https://lore.kernel.org/all/20240611133229.527822-1-nogikh@google.com/
should address that problem.

--=20
Aleksandr

>
> Thanks!
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANp29Y4ds327opXYv0VXyfZ0fT4srDjO5r9Y6grDZigARFfWaA%40mail.gmail.=
com.
