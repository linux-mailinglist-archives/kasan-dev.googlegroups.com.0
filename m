Return-Path: <kasan-dev+bncBC7OBJGL2MHBBC5C7OZQMGQEO6PU52A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pl1-x640.google.com (mail-pl1-x640.google.com [IPv6:2607:f8b0:4864:20::640])
	by mail.lfdr.de (Postfix) with ESMTPS id 5B70A91C203
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 17:04:45 +0200 (CEST)
Received: by mail-pl1-x640.google.com with SMTP id d9443c01a7336-1faafe0fffesf6760525ad.1
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jun 2024 08:04:45 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1719587083; cv=pass;
        d=google.com; s=arc-20160816;
        b=XY2NQ/PQ72yEEnH3uDb8iaJ8zOOu9w1jhmQ+WmJ76qz8jOqkrn/d4GOpATur28MOi8
         vpCQba/n6pIDuy1YwZPIzbo59GM6hh2KayW2tQw5DE0aa+nGOseFC+FiZxNOxUZcntIe
         CtkoygTOtqY/qBcD1OGPQRHasCXwASfpjgRWkTzeWhN2eqe60fLn77MVdWS20nq5TgTH
         xd5CWr0kSf9v9JkLRpmPjgRAEWeuEK+cl2hmvtS+mYtrYmVcuw3YsLYaNqZLfTfymZHs
         aU7lQDNP/1X71pJjFtt7bMxqdfIBfZT9OpwIdfq4ICiqpQsgxyRbFUex3ERZ/Vvs0N4R
         CD8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=ce6rxyJ0ZaWAW9tyIob4pTxklfpYKQeVyuM9YL8RHz4=;
        fh=t9IKbVrcqujSX3WWlh/3zygXCX+EFIFtq5+0ZZtlJYA=;
        b=ybmzLCJwTc6Avl+rW5nbdCb0YH42Br/VcdclIMxiEZcUgC+GNa91WmOpDZoGINHRal
         3mNrfF1XF/N3IHVuAwJFvYT+8CcwZAQK5RpzJNz9bhByBBic3gFHuxAkpqryI4X9PZ9+
         OeviT9NjgU1HMGAv8huEVkXc8zgNh5VEioNpyX+FLFCUWfBksKI3L5puhbRbbJHd/y8h
         q4EenhblxWqyWYwQRwNl2d/6lmsQu0u0HPUq5jJoK5gjQ6RdR8pX2cwAOBbG1l/FI27C
         5QECCv7lUV3BuxgP9bCv/tyLB5fit/I1HqzZ97f7fk3nNpzI1aJBI3jBSFwXWoZBiVpq
         61tw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1q8tJUSk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1719587083; x=1720191883; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version:from:to:cc
         :subject:date:message-id:reply-to;
        bh=ce6rxyJ0ZaWAW9tyIob4pTxklfpYKQeVyuM9YL8RHz4=;
        b=FCk5Pwslt33kUR5MuTNa9djODDWKTmsprwOPdcxN5lIybgWcnpW7YC0+VNuf3JDqr3
         YUU2gHJM3PycRiuT+pYTl7l+ft93Fv83IGviH7T2haPwxN6g+cy7+/kI7qFCWJsim0kK
         exLXxCRbU7Zm9lb9jQAZDxs2JfPx6tjqNVCQEWpJJW7KRXNpGXOZumbPnawuPD7sB7fP
         3zx0CL7KwvgVnZuYlZSkV+K9pJF8rmE00Jxb5xdUJ9NL7mDy6NMcP4rk8GiiY/Us73SR
         ZppJ5C1srr/rPJRhJJ0wv3+moiBYPJeVp5c22YwMqLrC2w0Rk0TpWXQABqKxZgbNJURr
         I9jg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1719587083; x=1720191883;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:cc:to:subject
         :message-id:date:from:in-reply-to:references:mime-version
         :x-beenthere:x-gm-message-state:from:to:cc:subject:date:message-id
         :reply-to;
        bh=ce6rxyJ0ZaWAW9tyIob4pTxklfpYKQeVyuM9YL8RHz4=;
        b=rJn9OOOvxvyYVgl5wFVglXdRoGLzkiUyM4ajQ9li4NYGqoKRaGUBwN27VEzetzuhOY
         YL50TFTVR475WtrnwTrCupBUf+wzJst4HFbHMxr+jkVmpsNK8oXOQo4w/UkOORoxHB53
         e/HdR6zUuR1UJfIQUAmyTN0GRw7ZzBPbm71DaKoCPVizCNqnmF1LL+woDPQK+b8QPeNA
         6U2P8dp5ngCJbg82fYYnvrR6BjnEsDcnQgb2wbtX2mY87FZBA6VXdSlDnyDGKB+Tjc5R
         okiQZ0Un8pBB7MDB10XRxHyPdPI4KfjK0rRSUJODQXxqr4Zeg9yqBrADZmjyP/ySPwfV
         6pBg==
X-Forwarded-Encrypted: i=2; AJvYcCVmZO+N1YkWXOd4yfUm82jLT3jjY8X61/yZUwyVfpon6dODj+9BErME1bht7n3remTgpZRG9EUVXlnNVm0YSlv6vmyNWP7mgQ==
X-Gm-Message-State: AOJu0Yz1L3sfo28LsW0BNk+9ZjYan+v8jcnkDbgRbULuw7icQvGwKWzF
	JV0XuuDXPV8ZTrWkGg/7IhbsC4U0ph7RRkY4wVkx8RacM0BxHlGc
X-Google-Smtp-Source: AGHT+IHBw0lznvEvPRszLN74+XnKJDklmtk3h0uHIziI/kjL4cvF+RnxqlyGR9miGFIByJjD0DaDjw==
X-Received: by 2002:a17:903:1c3:b0:1eb:6527:707f with SMTP id d9443c01a7336-1fa158fa99cmr179679385ad.39.1719587083403;
        Fri, 28 Jun 2024 08:04:43 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:e892:b0:1f7:34be:f997 with SMTP id
 d9443c01a7336-1fac4796b91ls6185295ad.1.-pod-prod-01-us; Fri, 28 Jun 2024
 08:04:39 -0700 (PDT)
X-Forwarded-Encrypted: i=2; AJvYcCWfosn6nTueiGis2D4WlJK2xNXUSSjOd2DHLFTDhliBa8I7Hs71JiF0Ta3sRjPC5yvbI7cbJl43Vc16UxmJ4+tSrIIyFNbEns9oGw==
X-Received: by 2002:a17:902:e810:b0:1fa:7f7e:2e18 with SMTP id d9443c01a7336-1fa7f7e33edmr84323435ad.46.1719587079541;
        Fri, 28 Jun 2024 08:04:39 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1719587079; cv=none;
        d=google.com; s=arc-20160816;
        b=kTNGkjpHEl9Gs5R09y+011mDMsDGdMRhpIOHaQUB8gd74MWbjDJ2EtxrN4nt11IZnB
         KpwmO21D9UxsQZodXl6rylazmfCGDONfl3JDc2v0dryfaych0fjvNI8mqoQmUufOfjoi
         HXoL8ozkp4EfrlMwTGVBvk+tPCEFWOv6khi6hyottw0c5WKv8TIRIzlyxGFzPHU/5C3w
         TzrblO2aSYoQFhQ6POMBrLmw+1NZlKu+jQAr6u6j1TbQAtIgXtvzRZ/sDpcBOfri6sAi
         8vgqA13KrV9+KZFMwYjw87LTerS38dI2r5oBBhm7lpPLFSpBKxK2UALXj8zjnsM/qbY8
         Cw7Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=IdPgPHdqxoeiATTbOh8/ckCue/94/+WvA2r7sPESkkk=;
        fh=7S9/WILGaQjhBhmvz1grkjAzR3+7DvU6Q5pSYVdx+FM=;
        b=DRs63vbtrvn4+TT5IlUt8c4HgproGf52SNN+4pF2X2Km6cR5xc5PrhftQxj2VtwHcb
         YYKIVG2heVBs3JMh+uxEji8L65O/5HiTdgbZ3pLp7ZgKmylqJnOufzSvcD2FPvaYNY0t
         VZhLukTwmqBAyuEpIXeAq2kC4QwD+zmTtvWo5ziIe2VOSPgUMoLpZqMZtpufYsFVnUPM
         p3VbFDSp/46pfPXhlUD2v7Ks2qTwDnzf2t6iKjnB8yySm8v8M9bBUBXex4ARcFPBWVTD
         48gvzo8CrFeQgK2geFY/jhWr9djKTZqax6GAf1lO7V5v9VEG6pl9f2sIspZyx3gCbN3C
         S59w==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20230601 header.b=1q8tJUSk;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x22a.google.com (mail-oi1-x22a.google.com. [2607:f8b0:4864:20::22a])
        by gmr-mx.google.com with ESMTPS id d9443c01a7336-1fac12f5b0bsi701935ad.1.2024.06.28.08.04.39
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Jun 2024 08:04:39 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as permitted sender) client-ip=2607:f8b0:4864:20::22a;
Received: by mail-oi1-x22a.google.com with SMTP id 5614622812f47-3d562b35fb6so418902b6e.3
        for <kasan-dev@googlegroups.com>; Fri, 28 Jun 2024 08:04:39 -0700 (PDT)
X-Forwarded-Encrypted: i=1; AJvYcCWijHkcG2Sza708c9QBXPIKDlA6vJBtSK9I9dGfI6/wUeUE0A0JQIWZ09oeP4vEXND6XANKHcZDNhkInNvLg3BqKMsAInr+Uy5QOQ==
X-Received: by 2002:a05:6808:1307:b0:3d6:2d2f:d03b with SMTP id
 5614622812f47-3d62d2fd33cmr4988807b6e.10.1719587078322; Fri, 28 Jun 2024
 08:04:38 -0700 (PDT)
MIME-Version: 1.0
References: <20240623220606.134718-2-thorsten.blum@toblux.com>
 <CANpmjNMHPt7UvcZBDf-rbxP=Jm4+Ews+oYeT4b2D_nxWoN9a+g@mail.gmail.com> <1bebf2e8a8a64b4aa4097fd045993106@AcuMS.aculab.com>
In-Reply-To: <1bebf2e8a8a64b4aa4097fd045993106@AcuMS.aculab.com>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Fri, 28 Jun 2024 17:03:59 +0200
Message-ID: <CANpmjNPoYaCVTHONGhN3ZJgd_yzUSMmjib+EBKbHG14xLnrQwg@mail.gmail.com>
Subject: Re: [PATCH] kcsan: Use min() to fix Coccinelle warning
To: David Laight <David.Laight@aculab.com>
Cc: Thorsten Blum <thorsten.blum@toblux.com>, "dvyukov@google.com" <dvyukov@google.com>, 
	"kasan-dev@googlegroups.com" <kasan-dev@googlegroups.com>, 
	"linux-kernel@vger.kernel.org" <linux-kernel@vger.kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20230601 header.b=1q8tJUSk;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::22a as
 permitted sender) smtp.mailfrom=elver@google.com;       dmarc=pass (p=REJECT
 sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Marco Elver <elver@google.com>
Reply-To: Marco Elver <elver@google.com>
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

On Fri, 28 Jun 2024 at 16:52, David Laight <David.Laight@aculab.com> wrote:
>
> From: Marco Elver
> > Sent: 24 June 2024 08:03
> > >
> > > Fixes the following Coccinelle/coccicheck warning reported by
> > > minmax.cocci:
> > >
> > >         WARNING opportunity for min()
> > >
> > > Use size_t instead of int for the result of min().
> > >
> > > Signed-off-by: Thorsten Blum <thorsten.blum@toblux.com>
> >
> > Reviewed-by: Marco Elver <elver@google.com>
> >
> > Thanks for polishing (but see below). Please compile-test with
> > CONFIG_KCSAN=y if you haven't.
> >
> > > ---
> > >  kernel/kcsan/debugfs.c | 2 +-
> > >  1 file changed, 1 insertion(+), 1 deletion(-)
> > >
> > > diff --git a/kernel/kcsan/debugfs.c b/kernel/kcsan/debugfs.c
> > > index 1d1d1b0e4248..11b891fe6f7a 100644
> > > --- a/kernel/kcsan/debugfs.c
> > > +++ b/kernel/kcsan/debugfs.c
> > > @@ -225,7 +225,7 @@ debugfs_write(struct file *file, const char __user *buf, size_t count, loff_t *o
> > >  {
> > >         char kbuf[KSYM_NAME_LEN];
> > >         char *arg;
> > > -       int read_len = count < (sizeof(kbuf) - 1) ? count : (sizeof(kbuf) - 1);
> > > +       size_t read_len = min(count, (sizeof(kbuf) - 1));
> >
> > While we're here polishing things this could be:
> >
> > const size_t read_len = min(count, sizeof(kbuf) - 1);
> >
> > ( +const, remove redundant () )
>
> Pretty much no one makes variables 'const', it mostly just makes the code harder to read.

This is very much subjective. In my subjective opinion, it makes the
code easier to understand and it'll be harder to introduce accidental
mistakes. For trivial cases like this it really doesn't matter though.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNPoYaCVTHONGhN3ZJgd_yzUSMmjib%2BEBKbHG14xLnrQwg%40mail.gmail.com.
