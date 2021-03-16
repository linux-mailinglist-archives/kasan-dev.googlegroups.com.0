Return-Path: <kasan-dev+bncBCMIZB7QWENRB2NDYGBAMGQEK7GSYZY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43d.google.com (mail-pf1-x43d.google.com [IPv6:2607:f8b0:4864:20::43d])
	by mail.lfdr.de (Postfix) with ESMTPS id 986E533CE00
	for <lists+kasan-dev@lfdr.de>; Tue, 16 Mar 2021 07:36:26 +0100 (CET)
Received: by mail-pf1-x43d.google.com with SMTP id f65sf2690076pfa.13
        for <lists+kasan-dev@lfdr.de>; Mon, 15 Mar 2021 23:36:26 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1615876585; cv=pass;
        d=google.com; s=arc-20160816;
        b=yfoZRZ9O+ka9fN5THQ86jZ+3Jop7M+qHq+mcIhwAkgwiVm5h71FQwmAt4rFUjiZe35
         iS4pQ0fsK5VtwupnVsRB10QN9WydbYeDVgnsNnNIbKTYwaIKMJN24rf4K0P6nn5oZTpn
         WZWHZU4864ZN2FwRDshjLzzBkLdbosmn4QU5WKd/Y5lhgshNQNju2zpYZ04XdS9s/fri
         VlBEvS6Tmas/afp37aig3ggjDBK6O+XRtKfqN/3hp8G1IUSnSlK4enodiP1CFccb3Kt4
         uUzex1S84YgN679oY1IxECrWDOIr8SSdICN+lC6ySsHJqCEjpd2RanZJyaauwHeDZVDX
         JuGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=xkm9LmKjS9UMWzSzrYwA5b//b2beMhxDRpyXut9EZfY=;
        b=n7OSmssVI8r50vfGrHW2ZaUi52Tn336Hg0O+oih7hurOWNW4bdrWIfXlMyVtaa5ApN
         8IlYS/XlC4tASwbtg5c9+CSFU1fECBoyazXMd5pFxcBQVR7O5uLMqm6yGSw2yOWWLRQ1
         qKJhIIAuOjtsE7DUXCSpZRwve/DF31cpQpUkxByi2dC1Cw1vk3PRvzhFAQ1keiC/p4IE
         f3wGB1uoGfTJEG1NQE96TvP33v59BDBatp7BRy/0y+4kdF6srQraQoTNxVqLKG/SDiQY
         ipHkO6vhQpVuNhxKPPHQvnCrHo34rO2CIwlvNN2ZxrdcNsvP+KL6RtvN4ydIin+TGj4K
         WmUw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ACpKI45I;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xkm9LmKjS9UMWzSzrYwA5b//b2beMhxDRpyXut9EZfY=;
        b=VMSMw+/u8viBY9IAqgu+1NtQ+yUg5VoDXoSUVsmIRxcP3JPPlg8gRjF+L1+LfuWQr8
         awnLNWVpWXslhXoyrROYrYADSNAXEUFYed0MwlUCvliA7uxnq3CBLnM2szwmUt6eUSWM
         W36CxS8PZQA9ujasWlfcyoB2SO5EH3g1IO8/nMpyQsPE8e4sgS7pZSXxKPmkEiZrmW6l
         LydGMCdmApUiOJUIZ11i+DTW/Zx/ocTt9UTg5bP4jXW2VWTCarwfK9fEsHvTkX1TvbDI
         8Eb2rilcsZkFKeeFOKfROmjAPgh+0gVR1gCIqehsZWCENDm7xN4jYv6nFtEnaWU/WVpk
         8Hpg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=xkm9LmKjS9UMWzSzrYwA5b//b2beMhxDRpyXut9EZfY=;
        b=TvFo/x+PWttv61CcnwW81Tk6v5hxGMLDMpeAWrRbBL91OalQSYxycIL/cq36FGHr/s
         8dNzSvBT4eo/BefwcN8oydELPlIPGcnGP/QVxalOecZLamcBR60z6/0JK8tn+Jq1AOsD
         f6+dPxf5Qa/YXokseg1m9TkrA9pg9Gc+QQTt8ifNZt6Wk/QnDV2tBzfkympnsWIUza3U
         5kXQgQ7fxsM/SJErtctCAu61pe5UpPJ1ps3AM/TR2jbHsVhU+xO/B3Oc7qHgfWhX2ZEz
         GrEWdpEdZdV+/PtqWfkdALJJFHgndimBk0PxXzO94vs+RDny4WkTfpXYDkPg+aDokljl
         F58g==
X-Gm-Message-State: AOAM533CEqLhTCNWX7cbc8Uvwyl245nh3wyrw6l/kfhc7ax/TYqLTaRp
	RJY26htTXqSss03RoT3iHvE=
X-Google-Smtp-Source: ABdhPJxNV2GjgkleymJ9sy9pX2FGmk4CY1psdObrwyX7QH29L3ysDYhuT3O368N5/SOp59DVuz/GnA==
X-Received: by 2002:a63:2165:: with SMTP id s37mr2603891pgm.145.1615876585389;
        Mon, 15 Mar 2021 23:36:25 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:903:4115:: with SMTP id r21ls10021870pld.1.gmail; Mon,
 15 Mar 2021 23:36:24 -0700 (PDT)
X-Received: by 2002:a17:90a:f2d4:: with SMTP id gt20mr3273269pjb.212.1615876584750;
        Mon, 15 Mar 2021 23:36:24 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1615876584; cv=none;
        d=google.com; s=arc-20160816;
        b=fECcmlYtAjeze9kWJQKQJsixGdu0S6Pv2EA6SO3mUROaWnMc5A/HgKv7XVVEbgyMoD
         BUwB54lU6TfhOpJ1VXwImewBqt+fb85z59WpFuz3cEhJYBABetGuxEeRNE3Eq8/Nq7ES
         vPAFV6dIoeH3R13cf+nUD4E2N9ifb27tYroZA7uflPn62ksgkdcK8eIS0cP/6XgGRF2p
         X1XzUhX2KWY6lkHtNUXZ2ZF0GidYwoymwceEe5eK9HS73S1aJyGLllAtn1sfq5qWLXuG
         7ySv4gmn6hMKTY+hx5Ht8sEl8uNAjCmZBgBZ8WEcycPxoU84s71QkgyUxy4jD139f4pf
         6gog==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=bx0hFpYvINElZV6pJjvCi8FeimInpCTokGRu0R++mJs=;
        b=Bv5Nq5V43r7T21IqJxkLCE7gU8weMrnLGOSThtCaN51eotfrEyoA46xb+vt5fsSC71
         cTF1AhB6ajR36p9MIB1JOgZRQueLOkNW0dBK70HQGQbs4DzLV2anFSZSshmNN1Oo1+Sq
         nn23FlhANvtwfBRn5DiyICwWG7NyLj5RtYdQT65wvbEexVcos8q/nH2dSZZXbsXgm2Zb
         4bnV98NmZ5bL3cc+cym1EbhqPtpnuyk+kJsKU0Mtvz2491fyTtksLkwcQ5iWwDyC1R5+
         AQCCzzEigtswr1jXONBUPu/cHmk8Wcotu+9hsr+q4RUHL86l6uhaLJ/dlUel3LO1dYIy
         oekA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=ACpKI45I;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x72f.google.com (mail-qk1-x72f.google.com. [2607:f8b0:4864:20::72f])
        by gmr-mx.google.com with ESMTPS id k21si1048060pfa.5.2021.03.15.23.36.24
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 15 Mar 2021 23:36:24 -0700 (PDT)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f as permitted sender) client-ip=2607:f8b0:4864:20::72f;
Received: by mail-qk1-x72f.google.com with SMTP id l132so34218525qke.7
        for <kasan-dev@googlegroups.com>; Mon, 15 Mar 2021 23:36:24 -0700 (PDT)
X-Received: by 2002:a37:96c4:: with SMTP id y187mr30363503qkd.231.1615876583744;
 Mon, 15 Mar 2021 23:36:23 -0700 (PDT)
MIME-Version: 1.0
References: <20210211080716.80982-1-info@alexander-lochmann.de>
 <CACT4Y+YwRE=YNQYmQ=7RWde33830YOYr5pEAoYbrofY2JG43MA@mail.gmail.com>
 <01a9177f-bfd5-251a-758f-d3c68bafd0cf@alexander-lochmann.de>
 <CACT4Y+ZPX43ihuL0TCiCY-ZNa4RmfwuieLb1XUDJEa4tELsUsQ@mail.gmail.com> <8841773d-c7d2-73aa-6fa6-fe496952f2ba@alexander-lochmann.de>
In-Reply-To: <8841773d-c7d2-73aa-6fa6-fe496952f2ba@alexander-lochmann.de>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 16 Mar 2021 07:36:09 +0100
Message-ID: <CACT4Y+bV1rCZrtbJtPaKeY=2q8MW8bLsB95rdAeRyUDR3fMsDQ@mail.gmail.com>
Subject: Re: [PATCH] KCOV: Introduced tracing unique covered PCs
To: Alexander Lochmann <info@alexander-lochmann.de>
Cc: Andrey Konovalov <andreyknvl@google.com>, Jonathan Corbet <corbet@lwn.net>, 
	Andrew Morton <akpm@linux-foundation.org>, Wei Yongjun <weiyongjun1@huawei.com>, 
	Maciej Grochowski <maciej.grochowski@pm.me>, kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:DOCUMENTATION" <linux-doc@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	syzkaller <syzkaller@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=ACpKI45I;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::72f
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

On Mon, Mar 15, 2021 at 10:43 PM Alexander Lochmann
<info@alexander-lochmann.de> wrote:
> On 15.03.21 09:02, Dmitry Vyukov wrote:
> >>>>  static notrace unsigned long canonicalize_ip(unsigned long ip)
> >>>> @@ -191,18 +192,26 @@ void notrace __sanitizer_cov_trace_pc(void)
> >>>>         struct task_struct *t;
> >>>>         unsigned long *area;
> >>>>         unsigned long ip = canonicalize_ip(_RET_IP_);
> >>>> -       unsigned long pos;
> >>>> +       unsigned long pos, idx;
> >>>>
> >>>>         t = current;
> >>>> -       if (!check_kcov_mode(KCOV_MODE_TRACE_PC, t))
> >>>> +       if (!check_kcov_mode(KCOV_MODE_TRACE_PC | KCOV_MODE_UNIQUE_PC, t))
> >>>>                 return;
> >>>>
> >>>>         area = t->kcov_area;
> >>>> -       /* The first 64-bit word is the number of subsequent PCs. */
> >>>> -       pos = READ_ONCE(area[0]) + 1;
> >>>> -       if (likely(pos < t->kcov_size)) {
> >>>> -               area[pos] = ip;
> >>>> -               WRITE_ONCE(area[0], pos);
> >>>> +       if (likely(t->kcov_mode == KCOV_MODE_TRACE_PC)) {
> >>>
> >>> Does this introduce an additional real of t->kcov_mode?
> >>> If yes, please reuse the value read in check_kcov_mode.
> >> Okay. How do I get that value from check_kcov_mode() to the caller?
> >> Shall I add an additional parameter to check_kcov_mode()?
> >
> > Yes, I would try to add an additional pointer parameter for mode. I
> > think after inlining the compiler should be able to regestrize it.
> >
> Should kcov->mode be written directly to that ptr?
> Otherwise, it must be written to the already present variable mode, and
> than copied to the ptr (if not NULL).

I would expect that after inlining it won't make difference in
generated code. Is so, both options are fine. Whatever leads to a
cleaner code.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbV1rCZrtbJtPaKeY%3D2q8MW8bLsB95rdAeRyUDR3fMsDQ%40mail.gmail.com.
