Return-Path: <kasan-dev+bncBDX4HWEMTEBRBEU4W76AKGQE33UGPBY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id 09DE4292CE5
	for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 19:34:12 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id d1sf413164qtq.12
        for <lists+kasan-dev@lfdr.de>; Mon, 19 Oct 2020 10:34:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1603128850; cv=pass;
        d=google.com; s=arc-20160816;
        b=bJvwdQ+u/ffUGJ3WRn6+StA9xOQ6yldlys9VYRbhfeFGxRJNQCgvvhJiruXYHlP5pI
         MtXSuLuyQB4FEW+rNeifvyA+1kUabrHJYKET8L183eVoHBwVoMzm8m867rkloP+WmwhB
         oHlGrNctHKDYu7FH8nTNc/i2kB+v8KTtEZzedWsjhbtcty4GEOlpacXX+qpnCyN9Sg7U
         G7x3RTxdSdmBGwO/Xw/lAlUVcOiC+dws2FiQ45E/hZYIlvZnDgzmz8OnY1f1uh7Ty3G3
         ozhHtrSIhGYnalVYUfD+nyNQPS9aypsDM0RNcROmDqTyZ+iLGu07VgdR6wm8hooiS1pA
         qq9w==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=RYiItPB+Fr1RvklHhfLCGQ/0Mq6GFFtPR8ZSYMfhiiM=;
        b=p6SbVFIyLIVdnYK1vh9uTmZG3IjkYn2KrrxW7KR+UOE4PqWaFu7SEsvtXVZCgucqQu
         Ox+Nt2kJ8ApPIqv1uLtcrNWqeyjsBYyfuR/CSHeFO3TFIKtpDz9uOSqcbSNSL0qAQahB
         gRg0/E2KeUV4WVd2lVwAoA4RKcTybCrdKSbFHUTW8LAGxBmR9JGmPIGJRgRD0SfjA4t+
         90G3lvrjo8z8BBGBzc++A57A8j7PKaNDE0BPfEOnnnqOMAk1dorTRKjBhjcm1uifskIm
         iucFHs7xVdEk0/uUSBlTmTF74LPGZkVJLWjGk3TTpLemahZG1TKrKAKIu24xeAPf8akD
         Fffg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bQfZ0uUm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RYiItPB+Fr1RvklHhfLCGQ/0Mq6GFFtPR8ZSYMfhiiM=;
        b=n76r8ZI/UD2aY++ggTeX/5zIf/BGoMDXsdISqeuPp+15YMY00om/TBwHEeReKi3loG
         kUAm4jlPdJ8jzUvWQRX59mtHTU1zTMr0aq37D8WqZQW8tEPRuY4OKDlPVXKMeHU1n+AQ
         TkJye4WBi7Bc1jcpvzsduALfnlmbTinVJ+9QUFA8wxBtgL1VhPbmNSZ4o9bqMJytjU9x
         BgShpN/t8fZNOtKDzUYZiPrvjpzm5oqY9tpgTDmO0G+qVGIw2rqZvDhNKRa0yQYtuFdI
         sCb7cKPo3nF9jZTxiUlGJy5iaA+WIziKqwRso3gVVre0CKmBvYPx7TNItvpNmkwnk1cv
         KyRQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=RYiItPB+Fr1RvklHhfLCGQ/0Mq6GFFtPR8ZSYMfhiiM=;
        b=ORt39VY4CstjuMSP9NTDSm4W2/GHMohnNLHSRYSoxUJOjgY5oAL6fezz/Cp92aW5by
         sBQcCahJ9kTOx8GvvvpHc6go/lJF1o5cI4uM691ObYG1kQBdPGX0b16PW/6WLZ4zyRMq
         fT87dUQoShtbLU5LnzqswcZ22Uhl1zUIbfkgoCbOLvExDA27Fy8CjXtZydTfAi5+k/+J
         JxdEdC5p9bLcwNeigKFqAi3+XZ2y7HQmWwWTAjkOZ4H+oSDDSEwqVTBb99hA12qFHTrp
         4MuvEIKEHCEV3azAfkBA67PaZ/X6iGKMyz7QXq56NMmUeOxu9Mh7mTqoKmvcLe9jRNr4
         7orQ==
X-Gm-Message-State: AOAM532swDUZQAy6i06aHdWPNvOTafK9ASRTsTg3fWxbhZRLArJEr+Hu
	0MVmgE0FhcGUMv0kxVbMpIM=
X-Google-Smtp-Source: ABdhPJz45o6pXMsWtESz9MInXy2T8DuD8M1hFN2IyvkQngp/NGupRKyz28MKlUY8n7CUDcHwY9fqtQ==
X-Received: by 2002:a05:6214:18cf:: with SMTP id cy15mr830950qvb.53.1603128850742;
        Mon, 19 Oct 2020 10:34:10 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:a8c5:: with SMTP id h5ls64105qvc.0.gmail; Mon, 19 Oct
 2020 10:34:10 -0700 (PDT)
X-Received: by 2002:ad4:4eaf:: with SMTP id ed15mr891080qvb.40.1603128850293;
        Mon, 19 Oct 2020 10:34:10 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1603128850; cv=none;
        d=google.com; s=arc-20160816;
        b=ZXszKXrHJ2TNS+eOpvASBlAaA8poyNHxkG2vbGfiURTLsHA5ZjV808H/kf3GKWsi76
         rcH0Mr+uaTxudr7XyiE82WSunnFuinhak9pAZG6X/KFs1DoWsdNbfqFLlivH50+SLOz7
         mnMKeE2RYImmDHGqWcGxrNjWqt9t3Tw8Ppz9Tf8mrqPN+Jjj013U+geopRDH8tcSksie
         I8m5GdqUpEGi1WF2T6tAvgTOokJqoak1h9Cn6MwS5aZVBWfetm7FqHx+cmqD7W2pSUN7
         0wVXuJE1mLoR06Xv7H2WfqydKZdFw/NeIdXU0jUOHvO5ahJ4kHkj6zX4LbPjuavxvNbp
         gBqw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=G5rjackHCXux/EOEOhw9b0KT9npfluDyAp2p7HpwGaQ=;
        b=glk33kcLJui/mYKq4N0BX0tS2dpCyPcul2TlXNGgB08D5y0jjnopt+UhnWEiftKRTa
         cL1sEWOriVwihGApAjG8zcK13w3Gt31vGLBYnph1QMkRsC0NMGAGZZzJzvRx0os0zizJ
         ZbBfWaWDnB4mVP/A5prWYfIK97eO2d3Jo+7hkiMvMNQvEP1zA+f8YDY4jU2jCJUP3JjW
         0TKg+b5FFFz8H4DotVh23ykJMCnjdok/j8K2sWCpVBgE/AM6Xa7DVOmxP2zUMmo6/SUb
         Vm23fWMdugXtZHjyUi2wBeVnOyJEXGEy40dr95FS2rDe1MzW7fCzuDIFnrzU9itGPST0
         sqYQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=bQfZ0uUm;
       spf=pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) smtp.mailfrom=andreyknvl@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-pg1-x542.google.com (mail-pg1-x542.google.com. [2607:f8b0:4864:20::542])
        by gmr-mx.google.com with ESMTPS id v35si43868qtv.1.2020.10.19.10.34.10
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 19 Oct 2020 10:34:10 -0700 (PDT)
Received-SPF: pass (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542 as permitted sender) client-ip=2607:f8b0:4864:20::542;
Received: by mail-pg1-x542.google.com with SMTP id b23so372934pgb.3
        for <kasan-dev@googlegroups.com>; Mon, 19 Oct 2020 10:34:10 -0700 (PDT)
X-Received: by 2002:a63:1906:: with SMTP id z6mr686372pgl.286.1603128849279;
 Mon, 19 Oct 2020 10:34:09 -0700 (PDT)
MIME-Version: 1.0
References: <44861eaca17ffbb51726473bc8e86ad9e130c67e.1602876780.git.andreyknvl@google.com>
 <CABVgOSnMiNHZoj36NfHTuQ3xLOu-W7FqMnE93cgJv465Kv1QUQ@mail.gmail.com>
In-Reply-To: <CABVgOSnMiNHZoj36NfHTuQ3xLOu-W7FqMnE93cgJv465Kv1QUQ@mail.gmail.com>
From: "'Andrey Konovalov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 19 Oct 2020 19:33:58 +0200
Message-ID: <CAAeHK+zrLvkkvQSjEt1r3uvj+W=xAx3gdroDF6eKeXuMQeZn+g@mail.gmail.com>
Subject: Re: [PATCH] kasan: adopt KUNIT tests to SW_TAGS mode
To: David Gow <davidgow@google.com>
Cc: Andrew Morton <akpm@linux-foundation.org>, Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>, Marco Elver <elver@google.com>, 
	Vincenzo Frascino <vincenzo.frascino@arm.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, 
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=bQfZ0uUm;       spf=pass
 (google.com: domain of andreyknvl@google.com designates 2607:f8b0:4864:20::542
 as permitted sender) smtp.mailfrom=andreyknvl@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Andrey Konovalov <andreyknvl@google.com>
Reply-To: Andrey Konovalov <andreyknvl@google.com>
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

On Sat, Oct 17, 2020 at 9:42 AM David Gow <davidgow@google.com> wrote:
>

Hi David,

[...]

> This looks good to me. Though, as you mention, writing to freed memory
> might not bode well for system stability after the test runs. I don't
> think that needs to be a goal for these tests, though.

We generally tried to avoid this, since we run multiple tests, and if
one crashes the kernel, the rest won't work. I'll fix this in v2.

> One thing which we're hoping to add to KUnit soon is support for
> skipping tests: once that's in place, we can use it to mark tests as
> explicitly skipped if they rely on the GENERIC mode. That'll take a
> little while to get upstream though, so I wouldn't want to hold this
> up for it.

This will indeed be useful.

> Otherwise, from the KUnit side, this looks great.
>
> I also tested it against the GENERIC mode on x86_64 (which is all I
> have set up here at the moment), and nothing obviously had broken.
> So:
> Tested-by: David Gow <davidgow@google.com>

Perfect, thank you!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAAeHK%2BzrLvkkvQSjEt1r3uvj%2BW%3DxAx3gdroDF6eKeXuMQeZn%2Bg%40mail.gmail.com.
