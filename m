Return-Path: <kasan-dev+bncBDW2JDUY5AORBNMF46VQMGQECIS2VBQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc37.google.com (mail-oo1-xc37.google.com [IPv6:2607:f8b0:4864:20::c37])
	by mail.lfdr.de (Postfix) with ESMTPS id 4D8108114E7
	for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 15:41:59 +0100 (CET)
Received: by mail-oo1-xc37.google.com with SMTP id 006d021491bc7-58d53348a03sf8486977eaf.2
        for <lists+kasan-dev@lfdr.de>; Wed, 13 Dec 2023 06:41:59 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1702478517; cv=pass;
        d=google.com; s=arc-20160816;
        b=Xfbw84PpxiugWcd2UZN3rUhwlsZry0HXZ1Djb7q687BOdT0FkmgucJ+pkk+KFXOy4B
         mDwSrplz30lwXM++qMpVgmP8lMsokxxNvMiMdlwvClJvd1oTHJ4I/dK2wZCMOm6KopnP
         ADzckgADxdXTWwvGZsEddr/hPr4QUoCWAQbMTuFQGWl77j5TkCxW+74vdl9vBcP52DZS
         9HM/PWZfNZ8H9sYtbNp909vBwpbisvbrxZbQvpdzGNfQcmfel3ihh7z7A47VdSdbJvez
         aMFB3BSmNBBOR+KtW114KBcnzJxoXaqhhuBwLWHpw3Zx6AOB64C7FcHNe2quNvS2Q8ic
         71FQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:content-transfer-encoding:cc:to
         :subject:message-id:date:from:in-reply-to:references:mime-version
         :sender:dkim-signature:dkim-signature;
        bh=jO1nfYidRKVRbbzxKXj09FywXAOXNt2el7VumfT5DY0=;
        fh=4GoNHihhI+tWJF1NFLFnJ4ihTBuEzThq1lQaveLpqU4=;
        b=DiIQ7Wa8fMbeE7oIyhGtntA5kRQMpp16SPbrB1RNnLxHnbiVIbqyvj8ncNOU+zBI/z
         +YTic+XC+WvlzGUYupZtn5VyGNZqIHHOJYZ+nIA20FX2eotdl7DQXF9XfY/B8MpNLvxA
         6elyg3vS5JbE626y8ssQ2oXQrqhdGpn2vXypYal+XMLgVG4/at/JOl/6j18GbWdxi2qx
         0LAMmlfB+X/VF31jkTj5xOctKtYEO/bw+8/zsk4tZed02WvRwWX4g8OTnbaz8fAZ/LLy
         uWHtrzzvjSM3NpSy2deIWQe3La+96vFhBYNsqztMbZKjQC87WaohjE0tjEEypcSO4bIR
         PyaQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Zu0cK7cK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1702478517; x=1703083317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:sender
         :from:to:cc:subject:date:message-id:reply-to;
        bh=jO1nfYidRKVRbbzxKXj09FywXAOXNt2el7VumfT5DY0=;
        b=r+ZG34yn9Zx50T6ITpM3AgAUjfIV3m/CRgmxpqvsy9KxKh2PCcChSzpQW3/If6DLn0
         Z77cts1WiYo8FVKasVOztYaWXmDoTZAOuPQB5af7dU05bNPOURAP2NzsC8wQHlG9Ue+e
         fPVzCg0LsiMzl5vjNncXsXd7htw0g4vbNmiXRvwOlgieazg8P5yGZEQugPSjnWKqgiRX
         Nvji0ilhdBlIlRWrU3D5BXByy+SMChPNRNHE0Oh9pPreUrOSNGdbhur1pJdV1000nAPY
         tVx50Dx8MEU0WHkexwc8+yylQT1XFZuulZoI1P+v1xRUOsS85eK62BDicFUUjxByteu2
         l4SQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20230601; t=1702478517; x=1703083317; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:content-transfer-encoding:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=jO1nfYidRKVRbbzxKXj09FywXAOXNt2el7VumfT5DY0=;
        b=TNCPPNfhRKJv52y4QncId3nJj7IgMCPnfMmRLIwiiPPyPLtUmqDfCXHmVtf/r4q+fh
         2mXKwYJX1qOdKhlGRKkNbOXUFGoiILcgc2B8HDZ0x8KmXsC/zsaZ51xMpwubCD5V36GM
         dY5tAgMCWxbKNLL8uRsO7c8X8QFin6vjOz3J2bEalAPjBexP2t+xhMq1MaVLnlRMjVmp
         T8pTDys3ZIDZCBfLW1w2fgHsy1zD/wyMbUEzk/UPpCV7dYHORupFOMMJaIcHKosmjHET
         6ig/GMy7Sdf3HZBKb6mAyT+dpp9srMD84tYMHSn8U0GuDV2e9dcK5I0D2QOs9ai0G8E9
         DWVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1702478517; x=1703083317;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender
         :content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:x-beenthere:x-gm-message-state
         :sender:from:to:cc:subject:date:message-id:reply-to;
        bh=jO1nfYidRKVRbbzxKXj09FywXAOXNt2el7VumfT5DY0=;
        b=eSZKy8JODP5eVEcYoZuVI8c4lqAC4UNemVLs8Ro5YrEcEERYYdSU3QHpROrdLnjxiF
         9knx6RT1xoCYzgdDVR3/KbYCi3M27uRiAJ0WfkMa7X7K+nGTv38lQQXtRcikLXpdywPK
         7vPf4UVsDWf7M1WYtpQbgV+KkEPW6nyRFKdsCR0O0KgSBUJ1hWcN+pMKPjt7gbJuqj0g
         PhD0NroLtyV9X0YfBfTAX3TJoHZgjvqZ+Yw5FW108SeHRA42A/81sgvFpxY8892TaRat
         xtEflhVEEVjJRBn+DcxTS8ypKKWodLPGNFZg6TiHfkXjbSuRDyty/04UYUhMbdwfVwY5
         NbiQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwZB+DIckpVUwFBTmL6FIAmnTnQrHisNkGnfqt3MVItC0vRJy0s
	+uasm7A20vVQ5mPOMhp9gZE=
X-Google-Smtp-Source: AGHT+IFugJuN/eTACsPAlpMm5PlWinzv50os221k/kkIKS+PgoNMUgSPTLnqLnF3Y/gqjPqlIM2YJQ==
X-Received: by 2002:a4a:92dd:0:b0:58e:1c47:76c3 with SMTP id j29-20020a4a92dd000000b0058e1c4776c3mr4955431ooh.15.1702478517669;
        Wed, 13 Dec 2023 06:41:57 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6820:22a9:b0:591:5e3f:d399 with SMTP id
 ck41-20020a05682022a900b005915e3fd399ls524949oob.2.-pod-prod-03-us; Wed, 13
 Dec 2023 06:41:56 -0800 (PST)
X-Received: by 2002:a05:6808:1443:b0:3b9:cca7:2f33 with SMTP id x3-20020a056808144300b003b9cca72f33mr9201805oiv.72.1702478516197;
        Wed, 13 Dec 2023 06:41:56 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1702478516; cv=none;
        d=google.com; s=arc-20160816;
        b=nEoNYMzjZ3SFH5/BO+IsuekMGgCrSN/QTg5mzfO8dcWzoYO2alJA//HRhChdM32Sta
         U+1ayyOUiUTh5DdNBwpiLrEjuSyC7pz5h5UMa217Kdf5ChOacUCqA2/8DLnfg/mlH2eD
         Io6M9WGd5bW2v3PhpFry3MzzqmsOZFHePIW5jkGmrG+QR3sj0bSO6hbxggbijvwdcH/y
         OFOhk25M4d4g1rHrjRhhY9ciHus5EKkSwUQ7nZGaPWTA9ksmzuhA9L1gzYcQzed+ctF9
         O+GS6kjCV/cHldUVBGGN4J4yKxtXbyNg9hAA99FeKBcIU7bSwD9Kwrwe2E3GxLGWMgL/
         AbrA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=ti4WWgukFD9JVeDjV7lFsBG44Mu7OstpF0433QBdo70=;
        fh=4GoNHihhI+tWJF1NFLFnJ4ihTBuEzThq1lQaveLpqU4=;
        b=t2rbCxwYviqpOf9aKPtxCW1D97OXwTAG7OA9IrWUfF0/cGED63nuGzTENqcuRWFxSo
         AHUf923DqkoIKJ/m2kSu6HVs2X6SN04AaokVY4XeWTM58roInIic7v8Ef7UGHAcUliJ6
         c8UF3HYwHD7buzB+BZ33CFqZ0jGOfVHuojBg0YfML7p0YpUJPWpQe2YdrhIlwVI2Epll
         2aj2ilGcXj28KPXXthJY/4Cvlb9UuA+qtf7jLzDzvu4+kuYVYg4k81eSYd4be88eQzs1
         Uoq8kvl79aNxTitQALdIScTB28OJNTcGL8LLUsxGyKHYXwnGrri2eWyZtfNcx1nYM7NQ
         dmng==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20230601 header.b=Zu0cK7cK;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-pg1-x52a.google.com (mail-pg1-x52a.google.com. [2607:f8b0:4864:20::52a])
        by gmr-mx.google.com with ESMTPS id gr5-20020a0568083a0500b003b2e5af8604si1123687oib.3.2023.12.13.06.41.56
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 13 Dec 2023 06:41:56 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a as permitted sender) client-ip=2607:f8b0:4864:20::52a;
Received: by mail-pg1-x52a.google.com with SMTP id 41be03b00d2f7-5c690c3d113so5724128a12.1
        for <kasan-dev@googlegroups.com>; Wed, 13 Dec 2023 06:41:56 -0800 (PST)
X-Received: by 2002:a05:6a20:9706:b0:18a:e86f:f246 with SMTP id
 hr6-20020a056a20970600b0018ae86ff246mr7813053pzc.10.1702478515453; Wed, 13
 Dec 2023 06:41:55 -0800 (PST)
MIME-Version: 1.0
References: <cover.1702339432.git.andreyknvl@google.com> <6c38c31e304a55449f76f60b6f72e35f992cad99.1702339432.git.andreyknvl@google.com>
 <CANpmjNNXiRxwTk4wGHL3pXmXo5YUY=VNLCf+g+kB6inXJnC2YA@mail.gmail.com> <20231212125728.1a275e704db4a5f5ca30e15c@linux-foundation.org>
In-Reply-To: <20231212125728.1a275e704db4a5f5ca30e15c@linux-foundation.org>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Wed, 13 Dec 2023 15:41:44 +0100
Message-ID: <CA+fCnZf85vFovXaxCuxTDCEQtMZMFKeKvo8UZ_9j8uhPEnqb+Q@mail.gmail.com>
Subject: Re: [PATCH mm 1/4] lib/stackdepot: add printk_deferred_enter/exit guards
To: Andrew Morton <akpm@linux-foundation.org>
Cc: Marco Elver <elver@google.com>, andrey.konovalov@linux.dev, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Vlastimil Babka <vbabka@suse.cz>, 
	kasan-dev@googlegroups.com, Evgenii Stepanov <eugenis@google.com>, 
	Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, linux-mm@kvack.org, 
	linux-kernel@vger.kernel.org, Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20230601 header.b=Zu0cK7cK;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::52a
 as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;       dmarc=pass
 (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Tue, Dec 12, 2023 at 9:57=E2=80=AFPM Andrew Morton <akpm@linux-foundatio=
n.org> wrote:
>
> On Tue, 12 Dec 2023 19:59:29 +0100 Marco Elver <elver@google.com> wrote:
>
> > On Tue, 12 Dec 2023 at 01:14, <andrey.konovalov@linux.dev> wrote:
> > >
> > > From: Andrey Konovalov <andreyknvl@google.com>
> > >
> > > Stack depot functions can be called from various contexts that do
> > > allocations, including with console locks taken. At the same time, st=
ack
> > > depot functions might print WARNING's or refcount-related failures.
> > >
> > > This can cause a deadlock on console locks.
> > >
> > > Add printk_deferred_enter/exit guards to stack depot to avoid this.
> > >
> > > Reported-by: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
> > > Closes: https://lore.kernel.org/all/000000000000f56750060b9ad216@goog=
le.com/
> > > Signed-off-by: Andrey Konovalov <andreyknvl@google.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > Doesn't need Fixes, because the series is not yet in mainline, right?
>
> I've moved the series "stackdepot: allow evicting stack traces, v4"
> (please, not "the stack depot eviction series") into mm-nonmm-stable.
> Which is allegedly non-rebasing.
>
> So yes please, provide Fixes: on each patch.

Sure, I'll add them when I mail v2 after we figure out what to do with
patch #2. Thanks!

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CA%2BfCnZf85vFovXaxCuxTDCEQtMZMFKeKvo8UZ_9j8uhPEnqb%2BQ%40mail.gm=
ail.com.
