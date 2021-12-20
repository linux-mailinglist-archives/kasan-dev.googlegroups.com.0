Return-Path: <kasan-dev+bncBDW2JDUY5AORBIXOQOHAMGQETIFWLLY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x140.google.com (mail-il1-x140.google.com [IPv6:2607:f8b0:4864:20::140])
	by mail.lfdr.de (Postfix) with ESMTPS id 897FD47B543
	for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 22:35:31 +0100 (CET)
Received: by mail-il1-x140.google.com with SMTP id e8-20020a92de48000000b002b1fa3d3014sf5851195ilr.23
        for <lists+kasan-dev@lfdr.de>; Mon, 20 Dec 2021 13:35:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1640036130; cv=pass;
        d=google.com; s=arc-20160816;
        b=R9ix7pmgefTLky5Ei+6blSz/+x+lmiRmekfuqhBhdiiSMGwWhXIIRjn/2I4NTYY96B
         aA9Qto3pi/rqa7yTFW+BGyMsSE8awCh5wQPr6nIoZWQ+5geMIfv2Ca54v/3Qg9Z5HI8a
         terUw6IBwnUc9l7kcfWeh7f92E0LcED01986HN2W7y3uuDq3bxHQi1ZJfK6t42Tbfmda
         X01KeNRnBrkztzQWq8kUWsFo0UuHLAryMqSNpgwUgryVkEOHk8g8UshihqvgulXbpGjZ
         XCu86ulYcPfgyxI7mHpOda9yi65tXOVfdon+PIUWrRc8yTt5fxqN/kMooo0I8WaHxact
         zbJA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=uV4HRyU18fWTuoAHyLkKXmlt/wL1u7yWkrq51b9MjBY=;
        b=TlSpIQredakhJy2rKEx39vSMwdJv6Rugl/6NgYPGQ50T/6+cGXwQxjASfB4NQ2KRKp
         NocYTYuZcpv8M0CjcxL06aeYuq25eKMyUd566O/t9U3Ui2wVwB9kaueZuNzXqOa8xJt0
         QvzGGbHnM9ONdvE9KUfOiN0HGzLFr5pIAQPQeYeV5jw4EBhZKVQz7sqW3ivk/rlI8Df2
         /mrc4VDu6UpCJz63ZvLVGfbNRsptEnIYt2+v+1mHO5FXcm0HCC2tye/OfM+T9XfONzf6
         e6AoZqyJSopG2nS0htSAkYRexU1SIPJBHWyVhmkavwood6pUaXOPTrrCI8ispZtqVwIa
         0ZZA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Fje853ZV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uV4HRyU18fWTuoAHyLkKXmlt/wL1u7yWkrq51b9MjBY=;
        b=qr2H9sQEHT0wEVZlhPfj7iCajH5cfeA0m3LxkL8wFajZnwW9rk8pwzhskV2ivVLyC5
         a3bvEWhm7IG5YE/xInBrPHc1hV4pjXYJGXgh7cLFmPKGYvGbgnyOtOZgF4v8SZqMjEbt
         /qIyUkKlNT2DjdxWemH5PkZZDv8JKBNUbsEf0LDnxhV0VmIWPXoJtmCr9aOY7V/4ytJm
         6ay6Jg0a7+Up2J5gQ5SBcqsuCDCCfEJXyOVVGoL7f3GcEcuikT4FNfsgJYGethAWve6l
         nY27XZDoPGo2qJuZofyz+4qEJ+pEecnG+XFHWBOrVgtcL3tUOUkS6q7SMYCGjjoyG86L
         4fnw==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20210112;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uV4HRyU18fWTuoAHyLkKXmlt/wL1u7yWkrq51b9MjBY=;
        b=W0CpT+FtarFwE7ylFJ7lOuxJNDtaRAkerdrge0x+r/SLZRhbDgEitg0LWE15xhx9/N
         8YuIc5rsGFMPdRINpr96Rbak/VDESfZl6F6Wpa0P3OlwS4PUk6XBvZddFOFbqqn8V+7+
         v7XykQXRvHZ6je3P6hyaKmqwk8OE3xjBUtrodzkrzM1VcqrY+jS3U4W4XRTt7E9acmIh
         kDkjiEJ4cs0lq1ELcTAv6ipSHMAwMYXZF+dDKcV4cAQIxg69EHUkQpkdCFJ7pcg/4J3T
         0/1ZFtJSgbpZIxqA4NlIrUAF2Fs7g+msHkNEGfo1Do39WP0OQuDfwAIBtDVmxQ3jeNbP
         B9mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uV4HRyU18fWTuoAHyLkKXmlt/wL1u7yWkrq51b9MjBY=;
        b=lnrtEP0E6gId43sHMj4Ftxv9jrgBFTSg7QanxMMpEZ3eM5cVhFmVs2E0lNcRYqh2+Q
         fUjVqi3ZGmffXW+hKz6E2E2MJfUd2edWylJMBcwzx+BlYJCxMQ4Wd4VhXs6A2ZXSARln
         9gOX6DaVq3b69TFO+OpaBwZqprXsiaVcS5ypxxuBLb3WFI1ImmAlXna3W9HePTeErOok
         k45oZmiuU+TPgoy4JolDRdnsV0fJxfdPnVlYU8lbwdN1w3WcUK7hUUfjTao7DZ4DeoGn
         pgWT6jnWSGLquPNb6sktYr5sJccRQqfbqNLMeGLf5YYUJBXgoEofif0LnrUs9S3FwDAK
         qZBQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530MgcjKqu/Yy/8lY8P8ACrtLISIh3ghD8t0mKbV03lbsgQWdYs+
	GKZNxULyyBAMOpVyQLymIs0=
X-Google-Smtp-Source: ABdhPJzZQXSjMuVouSBYl9GLDp87Xu2/yUBGzvbrHsyAvc9w3dfIqhXLZw9O0PCJmxaEXrscSK2E5w==
X-Received: by 2002:a92:db51:: with SMTP id w17mr9997619ilq.213.1640036130358;
        Mon, 20 Dec 2021 13:35:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6602:2d81:: with SMTP id k1ls1797012iow.6.gmail; Mon, 20
 Dec 2021 13:35:30 -0800 (PST)
X-Received: by 2002:a05:6602:2dce:: with SMTP id l14mr19650iow.193.1640036130059;
        Mon, 20 Dec 2021 13:35:30 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1640036130; cv=none;
        d=google.com; s=arc-20160816;
        b=XVm1EqdRik80SklQdnotbCjvlLY38nbzZhaZo9aXt2ZJ3SmuEuT4siFvP+Xwv4Vphw
         m3yVqJVHDQOf8IQc6NwVLfUPb3Ynm/rzZqjsuznaBGxUXhLhqCFLR9Isxr2ATIiEnTa4
         2dqUAWp8qlnbi0hlg8S+8iZZVrTQdlkP3dzQAHOE5PXLDsPFsMat+PKEwdI09b3kjJ0M
         WrwtMvYFh5xloKy/Sqnw9+7PpFYsF76+FwPnGJ5qUhlgobKHH0xIKO6M3mZamKVxADZr
         N1j8v6stXoRIET+uzjws0qhbroxeyIxkxhS5dfyPS5NT5M+JRqGj2EsmqTmwWvn6JhdL
         FC4Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=qcBG8nhHB+sRNlK7pbQ7JuxvUVpSVTkBiRPlBoBdveA=;
        b=IyYjTHTqLiI1pqs2TFRsebZnxDCscUHGp9wkv3h10dHiU+K8GcrM2SJpaF05PnrnD+
         Nt+OStj+/zztVZyLNevepxkxNN1nn1QVCn3ingUS9T2QKvS83EUoxu1bmGOSJVo0StZu
         AvAxzEAeuwircSO8N6fUs3PKmYLLo+uFxJPp6hRHmW+6ere4wlGFXVe+5EuwC7YW5ak4
         k8Yc+BIgjYY1zQG1QZD02hfeCsRuvy5kDtksL/7OO9j3+565CfZwCdMVyjmUdExZkBbn
         PaJSPevlQ9k3Jvn4r7Zoyh7Ff0GyrukzZRPRSlDDWG3Y4bozwci0asRVGmhXqaY0cRRc
         LEsw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20210112 header.b=Fje853ZV;
       spf=pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) smtp.mailfrom=andreyknvl@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x12b.google.com (mail-il1-x12b.google.com. [2607:f8b0:4864:20::12b])
        by gmr-mx.google.com with ESMTPS id 8926c6da1cb9f-2fc27949455si295170173.1.2021.12.20.13.35.30
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 20 Dec 2021 13:35:30 -0800 (PST)
Received-SPF: pass (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b as permitted sender) client-ip=2607:f8b0:4864:20::12b;
Received: by mail-il1-x12b.google.com with SMTP id w1so8648002ilh.9
        for <kasan-dev@googlegroups.com>; Mon, 20 Dec 2021 13:35:30 -0800 (PST)
X-Received: by 2002:a92:d58a:: with SMTP id a10mr9462133iln.81.1640036129810;
 Mon, 20 Dec 2021 13:35:29 -0800 (PST)
MIME-Version: 1.0
References: <cover.1639432170.git.andreyknvl@google.com> <1a2b5e3047faf05e5c11a9080c3f97a9b9b4c383.1639432170.git.andreyknvl@google.com>
 <CAG_fn=UWe_wo+E1P-1RyTPRAaSqXcCbhEwLaU=SJ+7ueGSysEg@mail.gmail.com>
In-Reply-To: <CAG_fn=UWe_wo+E1P-1RyTPRAaSqXcCbhEwLaU=SJ+7ueGSysEg@mail.gmail.com>
From: Andrey Konovalov <andreyknvl@gmail.com>
Date: Mon, 20 Dec 2021 22:35:19 +0100
Message-ID: <CA+fCnZfHHc9POqt_S78B=xHaqTRZy-5gr1Teix8o5g4jrz73bA@mail.gmail.com>
Subject: Re: [PATCH mm v3 26/38] kasan, vmalloc: don't unpoison VM_ALLOC pages
 before mapping
To: Alexander Potapenko <glider@google.com>
Cc: andrey.konovalov@linux.dev, Marco Elver <elver@google.com>, 
	Andrew Morton <akpm@linux-foundation.org>, Dmitry Vyukov <dvyukov@google.com>, 
	Andrey Ryabinin <ryabinin.a.a@gmail.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	Linux Memory Management List <linux-mm@kvack.org>, Vincenzo Frascino <vincenzo.frascino@arm.com>, 
	Catalin Marinas <catalin.marinas@arm.com>, Will Deacon <will@kernel.org>, 
	Mark Rutland <mark.rutland@arm.com>, Linux ARM <linux-arm-kernel@lists.infradead.org>, 
	Peter Collingbourne <pcc@google.com>, Evgenii Stepanov <eugenis@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: andreyknvl@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20210112 header.b=Fje853ZV;       spf=pass
 (google.com: domain of andreyknvl@gmail.com designates 2607:f8b0:4864:20::12b
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

On Thu, Dec 16, 2021 at 8:08 PM Alexander Potapenko <glider@google.com> wrote:
>
> On Mon, Dec 13, 2021 at 10:54 PM <andrey.konovalov@linux.dev> wrote:
> >
> > From: Andrey Konovalov <andreyknvl@google.com>
> >
> > Make KASAN unpoison vmalloc mappings after that have been mapped in
> > when it's possible: for vmalloc() (indentified via VM_ALLOC) and
> > vm_map_ram().
>
> The subject says "don't unpoison VM_ALLOC pages", whereas the
> description says "unpoison VM_ALLOC pages", or am I missing something?

Yes :) The title says "don't unpoison *before*", and the body says
"unpoison *after*".

I'll reword the changelog in v4 to make it less confusing.

Thanks!

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CA%2BfCnZfHHc9POqt_S78B%3DxHaqTRZy-5gr1Teix8o5g4jrz73bA%40mail.gmail.com.
