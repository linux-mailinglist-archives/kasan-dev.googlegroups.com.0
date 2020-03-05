Return-Path: <kasan-dev+bncBDK3TPOVRULBBZMFQHZQKGQELM4ILCI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x440.google.com (mail-wr1-x440.google.com [IPv6:2a00:1450:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id 9E51E179C99
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Mar 2020 01:08:05 +0100 (CET)
Received: by mail-wr1-x440.google.com with SMTP id t14sf1561911wrs.12
        for <lists+kasan-dev@lfdr.de>; Wed, 04 Mar 2020 16:08:05 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1583366885; cv=pass;
        d=google.com; s=arc-20160816;
        b=QO6DfcNJMsLz4X/juE9IrHNYKkOYjb0O8vtMLZ+mkouE3C1PRTH8Dv50BdntbOul1y
         ZNKypA1gUcDSuzy5OeD/NtL76b8Q7EByjdTq6uYY47S2sECmBSVIZFlCGH6jK7jTzrtn
         9qBaPyWXATH6av5nztQM/2H9uRQB3+3yaCNdRZqISBkpfpU1bObNBgabGRe9UBBq1OV1
         HXTNpRa/aCuSYJrUATxYgNe+ddTmMd7yD9H+/6p6rDiNjmyjIfsxO9P3TxXlFyRFzQd1
         ZMDn/yvO1/BFhjcaVkvNWCahhIFgqVc2tCX22sC+ccFubGjZ/MpSc/HOJtHaatqwFuM+
         D4rg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=hiRDBNiMVLX86Kf+E4s2Xa381Pa9UDfqQLWLDi9S33I=;
        b=CzcQKVaGM3N5F/rszgvnMMZQeLtEvvBeigmwnpN1CSbsJEdyFTkjqzgrKx7XZ2slwg
         mC48KH6sLfrnyz7ZJNOqLQlLnErJZxVgCk1RNVP4CW0O+Cvm4zYlvEt7DkKMmVGSpy58
         bE9+QD+PJZ9ywcwN4QyDEXvzfGDCjYQULu2aBMTRelDU/Og+8hCiNxwjpWNQXAg8cf5L
         wbMcVQdHhCdmGfy4J/WoHtmzWOwNoX8O6pk/3Ss9OQXrxYFKCBNmrJfADD+UI6B/RGBp
         5YtYfNMiEWxPllZFn+NwdhbQLmKXHSA4xhWeeoxy1rBh7CBqNm6mO2rkqGdE5/gTLmiO
         F+Ng==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a+BKBCwq;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hiRDBNiMVLX86Kf+E4s2Xa381Pa9UDfqQLWLDi9S33I=;
        b=eUBrhOd/L/hnNkU3y9+qwEU9WwDwI2kYIyVvyX7/AH3zpRDoLbdVK+G+3UVDCGdj/u
         K5OKWj9XlwZG+yYlax74v5Bx/QgphgPeM7XeJvxt/aHbc1ylNZFvkkDq3qToonNo9agn
         pP55xw4fs3CRH7hCcbCo5DjdIqcjmiA2qs4f2JCC/BvLsqUYH3B+JGUVzxijLT6vC2g8
         a/BNr6woOFTjduAb+VVYTG3bP4ijtyYx1s8MsH1UoqNhE9VUm/BEL0Q6Br4z5VgN25Q6
         o2/PbmlHsBKSlSvwgWV4tB+YT4+fHsCh8kNjeIMJn7pAxB2LwvFSCB2E+Qakzynyp8M7
         kxuQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=hiRDBNiMVLX86Kf+E4s2Xa381Pa9UDfqQLWLDi9S33I=;
        b=AIVaizlQ8BDgm0K4uT/QAHERE2sOj1sdUayR12fZ77vEqjaThNsIlKZ76J2/P9pftr
         R5XzaMOaR00lSJK6gTw7JMK9TtmclyvvMdBBPYunlwMJFcLPad1IO+naPZ7BMXAi5Bf5
         c2ASpb/OjTM26usiz1sh2KayjM2oWgyXe40QtyCm05rt9tzDCDIOAWzAqYoY4IAD0bUm
         mxANZ8/Ce/+ZF/PfVM0x5LQJEl/lhpzKdaT8jwSq6lABf2qtjCHQ8TN2OYzQ4Vd6p+xD
         xmJVFKcmbAigEf/+eCbT2MJcrQI7GAqhaaJ3B209nDooqtzfvTZtJseXwOWjFFiqFAMU
         cQRw==
X-Gm-Message-State: ANhLgQ3rvxPWUr8kEnjxQC/wSHnIyukB5e5vJjMRZUX1K68XGFaNIi/r
	7KOyExGCLbXp9R/Gblyr4H8=
X-Google-Smtp-Source: ADFU+vthSGA+zuzhXow8Tiao7BXdS1WCqRoVqC2gG/jyMfMXhjiNoeVNzt4GGf/YX6KTfHJBaInPww==
X-Received: by 2002:a5d:658c:: with SMTP id q12mr6900129wru.57.1583366885332;
        Wed, 04 Mar 2020 16:08:05 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:adf:dd81:: with SMTP id x1ls270207wrl.1.gmail; Wed, 04 Mar
 2020 16:08:04 -0800 (PST)
X-Received: by 2002:a5d:4247:: with SMTP id s7mr6851321wrr.66.1583366884826;
        Wed, 04 Mar 2020 16:08:04 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1583366884; cv=none;
        d=google.com; s=arc-20160816;
        b=yhvf/ygR2MhYQH9LJ0bMpwfcol1Xz6+UghR9W4WI2+zAu4zC31+4HFI/TGH/Mj4phI
         eJx/nOQZ7e8LqJQ82cMUODpDLeowunCTQ7YBB6re/gjQUIR6v4KnuYjcn161ZOPZ1Svf
         pfjNpcqIaS1feIeYqgS/zAMUe0kYtR7e++BiE+nzGKO5UBjik/fiSRjCQWF6xb9NvrbM
         +UwCcqnfJKh+7hzaieW/1YHqXu+cIsjtVDe3BkQ/JjJUJ6IiQ6j00VL/8wiyKdCBVjor
         Zf7iFJXOyQ+pLpj2fdLA/xh9XVOunDZhhLsXfefw+rtDHkwJ9XOwSa2z6sJ47mpreJ4O
         gOUA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=rhh6IhNFfdTMDzn5raC/7ABRe9JvD2oPC8LGUlDP/90=;
        b=EtJYG6R2LbEkbF1Cxlm42UdaFUYcUPEf9JupDTLUAoKoXRK/GKWqh0mVPQI2Z9QwYc
         NkKjVxmtShIlu0T9jNqqjXwpN2O6h0EEctlr7i7lsdirJWKIn8YSPKHbByF9BcCsMPlB
         LNUjfxjH15k/01CVhOdlKpqdHb45fQ7sv+louB8ewOlDm6Oet+ftANVTGcw9jVJiThwh
         Qdz/cvgxOC6v5mA4PJdcCxEHoH7NLkXNe01GgxOZeKQTwjF7/QahuAPQJ8y2mQQdHqdo
         rt0oGdKrms1dHlWtJQaUOWwXYmWRDrr04pW+HbLqKbAm3RrgGJZPTIbO2sBotsjVMfao
         VYlg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=a+BKBCwq;
       spf=pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) smtp.mailfrom=trishalfonso@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-wr1-x441.google.com (mail-wr1-x441.google.com. [2a00:1450:4864:20::441])
        by gmr-mx.google.com with ESMTPS id d14si177269wru.1.2020.03.04.16.08.04
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 04 Mar 2020 16:08:04 -0800 (PST)
Received-SPF: pass (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441 as permitted sender) client-ip=2a00:1450:4864:20::441;
Received: by mail-wr1-x441.google.com with SMTP id v2so4803867wrp.12
        for <kasan-dev@googlegroups.com>; Wed, 04 Mar 2020 16:08:04 -0800 (PST)
X-Received: by 2002:adf:ee02:: with SMTP id y2mr720131wrn.23.1583366884150;
 Wed, 04 Mar 2020 16:08:04 -0800 (PST)
MIME-Version: 1.0
References: <20200227024301.217042-1-trishalfonso@google.com>
 <20200227024301.217042-2-trishalfonso@google.com> <CACT4Y+YFewcbRnY62wLHueVNwyXCSZwO8K7SUR2cg=pxZv8uZA@mail.gmail.com>
 <CAKFsvUJFovti=enpOefqMbtQpeorihQhugH3-1nv0BBwevCwQg@mail.gmail.com>
 <CACT4Y+Y-zoiRfDWw6KJr1BJO_=yTpFsVaHMng5iaRn9HeJMNaw@mail.gmail.com>
 <CAKFsvU+ruKWt-BdVz+OX-T9wNEBetqVFACsG1B9ucMS4zHrMBQ@mail.gmail.com> <CACT4Y+b5WaH8OkAJCDeAJcYQ1cbnbqgiF=tTb7CCmtY4UXHc0A@mail.gmail.com>
In-Reply-To: <CACT4Y+b5WaH8OkAJCDeAJcYQ1cbnbqgiF=tTb7CCmtY4UXHc0A@mail.gmail.com>
From: "'Patricia Alfonso' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Wed, 4 Mar 2020 16:07:52 -0800
Message-ID: <CAKFsvUK84pD+K5rTbvKXB0MyW9XCknpSfMAO28iQ4S1=WBQK6Q@mail.gmail.com>
Subject: Re: [RFC PATCH 2/2] KUnit: KASAN Integration
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Andrey Ryabinin <aryabinin@virtuozzo.com>, Brendan Higgins <brendanhiggins@google.com>, 
	David Gow <davidgow@google.com>, Ingo Molnar <mingo@redhat.com>, 
	Peter Zijlstra <peterz@infradead.org>, Juri Lelli <juri.lelli@redhat.com>, 
	Vincent Guittot <vincent.guittot@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, 
	"open list:KERNEL SELFTEST FRAMEWORK" <linux-kselftest@vger.kernel.org>, kunit-dev@googlegroups.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: trishalfonso@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=a+BKBCwq;       spf=pass
 (google.com: domain of trishalfonso@google.com designates 2a00:1450:4864:20::441
 as permitted sender) smtp.mailfrom=trishalfonso@google.com;       dmarc=pass
 (p=REJECT sp=REJECT dis=NONE) header.from=google.com
X-Original-From: Patricia Alfonso <trishalfonso@google.com>
Reply-To: Patricia Alfonso <trishalfonso@google.com>
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

On Tue, Mar 3, 2020 at 10:23 PM Dmitry Vyukov <dvyukov@google.com> wrote:
>
> On Wed, Mar 4, 2020 at 2:26 AM Patricia Alfonso <trishalfonso@google.com> wrote:
> >
> > On Sat, Feb 29, 2020 at 10:29 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > >
> > > On Sat, Feb 29, 2020 at 2:23 AM Patricia Alfonso
> > > <trishalfonso@google.com> wrote:
> > > > >
> > > > > On Thu, Feb 27, 2020 at 3:44 AM 'Patricia Alfonso' via kasan-dev
> > > > > <kasan-dev@googlegroups.com> wrote:
> > > > > >
> > > > > > --- a/tools/testing/kunit/kunit_kernel.py
> > > > > > +++ b/tools/testing/kunit/kunit_kernel.py
> > > > > > @@ -141,7 +141,7 @@ class LinuxSourceTree(object):
> > > > > >                 return True
> > > > > >
> > > > > >         def run_kernel(self, args=[], timeout=None, build_dir=''):
> > > > > > -               args.extend(['mem=256M'])
> > > > > > +               args.extend(['mem=256M', 'kasan_multi_shot'])
> > > > >
> > > > > This is better done somewhere else (different default value if
> > > > > KASAN_TEST is enabled or something). Or overridden in the KASAN tests.
> > > > > Not everybody uses tools/testing/kunit/kunit_kernel.py and this seems
> > > > > to be a mandatory part now. This means people will always hit this, be
> > > > > confused, figure out they need to flip the value, and only then be
> > > > > able to run kunit+kasan.
> > > > >
> > > > I agree. Is the best way to do this with "bool multishot =
> > > > kasan_save_enable_multi_shot();"  and
> > > > "kasan_restore_multi_shot(multishot);" inside test_kasan.c like what
> > > > was done in the tests before?
> > >
> > > This will fix KASAN tests, but not non-KASAN tests running under KUNIT
> > > and triggering KASAN reports.
> > > You set kasan_multi_shot for all KUNIT tests. I am reading this as
> > > that we don't want to abort on the first test that triggered a KASAN
> > > report. Or not?
> >
> > I don't think I understand the question, but let me try to explain my
> > thinking and see if that resonates with you. We know that the KASAN
> > tests will require more than one report, and we want that. For most
> > users, since a KASAN error can cause unexpected kernel behavior for
> > anything after a KASAN error, it is best for just one unexpected KASAN
> > error to be the only error printed to the user, unless they specify
> > kasan-multi-shot. The way I understand it, the way to implement this
> > is to use  "bool multishot = kasan_save_enable_multi_shot();"  and
> > "kasan_restore_multi_shot(multishot);" around the KASAN tests so that
> > kasan-multi-shot is temporarily enabled for the tests we expect
> > multiple reports. I assume "kasan_restore_multi_shot(multishot);"
> > restores the value to what the user input was so after the KASAN tests
> > are finished, if the user did not specify kasan-multi-shot and an
> > unexpected kasan error is reported, it will print the full report and
> > only that first one. Is this understanding correct? If you have a
> > better way of implementing this or a better expected behavior, I
> > appreciate your thoughts.
>
> Everything you say is correct.
> What I tried to point at is that this new behavior is different from
> the original behavior of your change. Initially you added
> kasan_multi_shot to command line for _all_ kunit tests (not just
> KASAN). The question is: do we want kasan_multi_shot for non-KASAN
> tests or not?

Ah, yes. I thought your first comment was suggesting I change it from
printing all KASAN tests by default because the intended behavior of
KASAN is to only print the first report. I think I'll pose the
question back to you. Do we want kasan_multi_shot for non-KASAN tests?
For functionality sake, it is only required for the KASAN tests so
this is more of a judgement call for the user experience.

--
Best,
Patricia Alfonso

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAKFsvUK84pD%2BK5rTbvKXB0MyW9XCknpSfMAO28iQ4S1%3DWBQK6Q%40mail.gmail.com.
