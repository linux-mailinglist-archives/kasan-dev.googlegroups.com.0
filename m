Return-Path: <kasan-dev+bncBC7OBJGL2MHBBQGDY33QKGQEBGP2GXQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 5136E2049F2
	for <lists+kasan-dev@lfdr.de>; Tue, 23 Jun 2020 08:31:29 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id n11sf23053946ybg.15
        for <lists+kasan-dev@lfdr.de>; Mon, 22 Jun 2020 23:31:29 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1592893888; cv=pass;
        d=google.com; s=arc-20160816;
        b=tgXTw+NpMsl+jqdYVawtywa38q3LR3LUVX0rhpBvU/uN2iy5hSYMlwGJVTsWpvjEov
         TbhV3SlgcH7JJFU4YyjkQRtbxFOsM9GgVriG4Mk7zeOixcD+0RiR7qQ1UmUHwD0PDhDM
         yEDkG6utYXqjKIWMoV8mT6BRQmT2vAWlWoxkCyEIempiHDRg2y7hrk/MqMNTDG3Fxbab
         OsU1jVirh9mP3KRFEM8SNLHYFenTIiPVUOsrlCKwGky2R8p29e6yf5f9DWTeF3/hzXuY
         al5He26y4YCcY+jzxtscmH3gvZx+7/DPGa8cr1vfjXRC+3wboEVuS7JsotXliIk4mdfn
         q3LQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=tAty2/jHm6vnHWVy+bobgyi77C+Gk2Ot0Bo3xAQ5M00=;
        b=CRB50KAeqIROSehpPH8x7CssipcxQ5yqQ0xsBJWzISuQfnGRJRE75CUT4ezADy4vMi
         nGC3RTzCc/TsG2Lr7AUd61SewcihnBuDgpG9bhLnCnXuGvEguH8P9HPVWwIhCYRcgTqa
         l1TRLNMGi+L7+iENw5zxriQL8HmGWh9eNeZhz9mEpW/yYAzo3WCmy85Xex4zb+exraTc
         A4CXj60wwcD4NRcF6YQmnOPmhX0ElKQdAvcB70+qBgNtvoxhBxJeVuxNgc3xuL+ZyqFS
         qTtL4i6t/QMjy/PhYumI3Co8ibdUuPyxopyWBbseJchgkwFDmnOhVnKL1yrdKon7u6hR
         KauA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wUBnFpb1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tAty2/jHm6vnHWVy+bobgyi77C+Gk2Ot0Bo3xAQ5M00=;
        b=TaKdk+Tzhg7XP1l5Z1hmO3U52QxNgzIXjU5EottDbLLykecb4Kbi7iZ/h4cs7XWk7d
         VGEN1OhIlF1EE7opZ0dpvor0Hh+3E/EuObN5klcKHhBn495kxds1+UgTwYLqtgwy/h+2
         GYKioroHj4yG6SkMRfkUqNHLhYEIfa7xLZ3+In5gNlZo0KLFu91QK1khvaoPAW7xxHJH
         WTxO1l9a56ZFeZrnXcwA1NzDoxNYxv9inm5d2yAp1/mDkKi86FslUN07lEUpEOK46F87
         wxRX999rZFLSFaspKYpRpn3A8SYhygyKQzxui/itejQ94Y/Oe3IVnnrSpANfPtKsAf3/
         nYlA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=tAty2/jHm6vnHWVy+bobgyi77C+Gk2Ot0Bo3xAQ5M00=;
        b=lCShoSxl3Vfz8iWuUAGM+aOzGzB69cCplPQ26Hesm0tnfOIkwcDW1KMTkES0EQ94Ci
         DiDW3GK7uDQ5ic7CdSJ0L0I5Rv7poH6U1vNTw2naKcaVhgsKQ/1f1O7oh2SxOVzGHNfv
         ZVZ0JokGYfZLxRlTHcXZLejSgyx/p141/ZZYXRZkiBoFQLBhvpCuQvQJJ4N9+fjJYyap
         uMakMLMuTSkvogRZIrzaWgVuNPkOkZJcX/BiY8efwx6w1k0wO6G2sxF/XD0uygpDKmLz
         tzcj8BbtaleYRrNEptSkj1FvcLQ4XQzZrVNzzhTT0+AKDej/2ZMMoHd+x0BkzOdQGXSx
         ioVw==
X-Gm-Message-State: AOAM530AUU63Hlsd/Rtg1Y26tAJgvu5TboWqPNwZcgqdZfrjnBHwtne4
	YHgIHedogYgYo7Sysc9zizE=
X-Google-Smtp-Source: ABdhPJyrp272e+vcfUHe5VH5+g/zBmwZKLueiAj3HcM6vTA+03Nb2ZxlkiaV6W2jlydw/uLu6L7g0A==
X-Received: by 2002:a5b:886:: with SMTP id e6mr32310401ybq.318.1592893888340;
        Mon, 22 Jun 2020 23:31:28 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:7003:: with SMTP id l3ls7407205ybc.2.gmail; Mon, 22 Jun
 2020 23:31:28 -0700 (PDT)
X-Received: by 2002:a25:9345:: with SMTP id g5mr33077433ybo.485.1592893887983;
        Mon, 22 Jun 2020 23:31:27 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1592893887; cv=none;
        d=google.com; s=arc-20160816;
        b=A+a7jGCnEfvz1c9FYybpHBYc6rj+RlLov7vIO9A/GKPMc/p7vPZVHeuuep3j/5wLDS
         CBpJloITNuE3ai6dK4BOay+6qplHKA5HI274X8lXyWQuw+PSShH6Pr+fVgcGDnqb1UB+
         1iTyBTLuKuWyyc2WTmN3m/vuQrRu5qhCnEzguxqaNpjBka37fQI6S8gCHEGl9FDHVwAC
         1bSNt2dENII7td5FrYn66RJsfA5c6YlB4h0KsbK5YYCO4o4GCCukK9y0d4Lk1KA2uzjh
         HB5Nietn1Ytu3o0H0woZqx0qTtRNBR7m92vsHEcEsgAblhedSPyg1brnlg6qsc2VEY0J
         X7Eg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=Qmek8AIjwhUpjq4ifIiYp8uzWRuQrceKBuTssA8WgU4=;
        b=RzsK8ChG/GJTIxp1Ak38AWq0gTvbxFjfUfcZoMygIMZLoWiNTZMaSyy0mIfUOvFEtb
         HO7Tn4WZAH5ZA0G51MVzkgs0Hbwkmz94BPQ9FGEAMSmh8ZY6GC0rnoSPWaYMeXyXfDZr
         q7yOR3GOipN4O/Jt80qHcBCYO7ZlqluD+cqz2bfIstqkd2lEGNIpG6jYpso5NmdcD9gZ
         7njXHTWVvfUJDO1hYWwZ6nWpwJcAeG5C7BX5NL51jB5ovnplhMVDiL+4aTqgjbjky/po
         bxyBhogsCsbotsvc99VwHCES4zZ8fAZC4edftiPiLOQQIpSH7/5rW9cw69tn61CLv05f
         asDQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=wUBnFpb1;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-ot1-x342.google.com (mail-ot1-x342.google.com. [2607:f8b0:4864:20::342])
        by gmr-mx.google.com with ESMTPS id v16si1359584ybe.2.2020.06.22.23.31.27
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 22 Jun 2020 23:31:27 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as permitted sender) client-ip=2607:f8b0:4864:20::342;
Received: by mail-ot1-x342.google.com with SMTP id t6so15453695otk.9
        for <kasan-dev@googlegroups.com>; Mon, 22 Jun 2020 23:31:27 -0700 (PDT)
X-Received: by 2002:a9d:58c9:: with SMTP id s9mr18209710oth.233.1592893887231;
 Mon, 22 Jun 2020 23:31:27 -0700 (PDT)
MIME-Version: 1.0
References: <20200623004310.GA26995@paulmck-ThinkPad-P72>
In-Reply-To: <20200623004310.GA26995@paulmck-ThinkPad-P72>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Tue, 23 Jun 2020 08:31:15 +0200
Message-ID: <CANpmjNOV=rGaDmvU+neSe8Pyz-Jezm6c45LS0-DJHADNU9H_QA@mail.gmail.com>
Subject: Re: [PATCH kcsan 0/10] KCSAN updates for v5.9
To: "Paul E. McKenney" <paulmck@kernel.org>
Cc: LKML <linux-kernel@vger.kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	kernel-team@fb.com, Ingo Molnar <mingo@kernel.org>, 
	Andrey Konovalov <andreyknvl@google.com>, Alexander Potapenko <glider@google.com>, 
	Dmitry Vyukov <dvyukov@google.com>, Qian Cai <cai@lca.pw>, Boqun Feng <boqun.feng@gmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=wUBnFpb1;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::342 as
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

On Tue, 23 Jun 2020 at 02:43, Paul E. McKenney <paulmck@kernel.org> wrote:
>
> Hello!
>
> This series provides KCSAN updates:
>
> 1.      Annotate a data race in vm_area_dup(), courtesy of Qian Cai.
>
> 2.      x86/mm/pat: Mark an intentional data race, courtesy of Qian Cai.
>
> 3.      Add ASSERT_EXCLUSIVE_ACCESS() to __list_splice_init_rcu().
>
> 4.      Add test suite, courtesy of Marco Elver.
>
> 5.      locking/osq_lock: Annotate a data race in osq_lock.
>
> 6.      Prefer '__no_kcsan inline' in test, courtesy of Marco Elver.
>
> 7.      Silence -Wmissing-prototypes warning with W=1, courtesy of Qian Cai.
>
> 8.      Rename test.c to selftest.c, courtesy of Marco Elver.
>
> 9.      Remove existing special atomic rules, courtesy of Marco Elver.
>
> 10.     Add jiffies test to test suite, courtesy of Marco Elver.

Do we want GCC support back for 5.9?

   https://lkml.kernel.org/r/20200618093118.247375-1-elver@google.com

I was hoping it could go into 5.9, because it makes a big difference
in terms of usability as it provides more compiler choice. The only
significant change for GCC support is the addition of the checking of
(CC_IS_GCC && (....)).

Thanks,
-- Marco

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CANpmjNOV%3DrGaDmvU%2BneSe8Pyz-Jezm6c45LS0-DJHADNU9H_QA%40mail.gmail.com.
