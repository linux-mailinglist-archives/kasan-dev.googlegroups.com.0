Return-Path: <kasan-dev+bncBCMIZB7QWENRBA6XUPXQKGQEAMYFCIQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x43e.google.com (mail-pf1-x43e.google.com [IPv6:2607:f8b0:4864:20::43e])
	by mail.lfdr.de (Postfix) with ESMTPS id DE11611402E
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 12:35:32 +0100 (CET)
Received: by mail-pf1-x43e.google.com with SMTP id s25sf1642166pfd.9
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 03:35:32 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575545731; cv=pass;
        d=google.com; s=arc-20160816;
        b=YnqajpJpXdEYGeQ4nPB4IFvJHe3mCjr3ypkrCmPkHT8kWqbfpwtMhFRAr3g4exk54m
         5UXMCR/wtBOKpMr/tmEqomYjMAZok+vuTlYA0W8Q7g+1F4/6MjZJwsmQy1ogTwF7cM6g
         wlzjdjEBLRnvlUxtctTP6iV2he6KCsCiRrgeKY3fdP3CLYqCzO6HARgsOQZePvADArOB
         p8ihEmeabb43rWvcyT4FStWbphJjoAd3s9kMScHyYBYth7pHvnyVNw5WdJAgi0ZL8A3X
         MYz7pNSMo4Yu6iyMAgTym0JeOtunvsPxR9Qj5Ab/RM5aquor6YhdYNyqraqpd9ODtkCZ
         vFSg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=+ZiS/6vmBX7rn+p+wHdof0vLupx6FWgjfCw7uNehLag=;
        b=m1IdD74Ol5cqiDlXynznizHABXGiMuIPBDsGXWXrA96xN7SBHkW/IiVxDaatB7TWEB
         6SQh8iusv8ZkzsUgAOqxARSwEbNiHPjwiutlntVQHGNnx6Y8XhUiO0Teeby/lQ7z862A
         fLQN6ZiR2nnCxIOH2himSFYtUaRZMYFI6F/GwzZpr1Zaqy/y8ndKqYjPxa8EMiccSukp
         A2VxIB4i/GFEprFMyLQEudUY5yLcQLJPq0BWWk4J7/4HidTIRbpOOIFuBoIWsrF55Xj8
         KIhW+DivYdywu/NoLT3NrF41TRMNrTCV67mXwAgt83Lv6PyqB9zMhg/XC5DsnuoS3iqu
         4m6w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VLVyGXFm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ZiS/6vmBX7rn+p+wHdof0vLupx6FWgjfCw7uNehLag=;
        b=Plfx9bGOPmvGWNzGGfnUXIe5hHc08hk6k1DtRJmKgeW50P/l7ABilKymPSqr3PSyx0
         xpyNfxeLM/5SUJcb5nkoIJg35tt6AeVT0j4o7zr+ZXM9yTJYQyLmhySNKDTKDfAFtVhZ
         SoUS/SGo3BcCUgt2DLWU3H9XzjWGB8XqNc6p18kRpa4cV2Rlx+D19goGVZXn2BB2XlWu
         5Vhk8cbg8L/rTVaNiaKG2j3TIrrlyEWs/Km6j6jnBflZiyO0wedGyQaKVV1GsTw97Sti
         RoNoNC+fgwdY6zwBORUetOGv/1n1K5+bPHXLebl/naaN2166Si9ZE8EVmaMrxt/zw/Ho
         tPbQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=+ZiS/6vmBX7rn+p+wHdof0vLupx6FWgjfCw7uNehLag=;
        b=rV3plkynyw2AC5LTN206RcgsFYkqDZo6Mj0Tirwo43VKhzegvxlJU/ZTFGBiJxD3/7
         Y6Qw3EzKJIXndg0A/kBh+MGUvmA6m8UnhVA252thy2Nx5beSh7hkG+Dra77LDppOrSIm
         74euTZMPM2s8pX1+17kD8N+n+OzxvE4dNBHCkvEhO3oTSBG0ys2drdmmRhXtrJTWSQ1O
         WAeYGl2HmGrNJI2qmbXMy+CvrC/brxj2w/8TTqzd8nqysSI55CdaYaNw1Rw4xkORHE4u
         HcfZFbrFEmD82GhpipcdxR8b6ECA7nRAMmWD9nH5P8Fly0nx5rGMCoQu1nqdh37JUi3N
         SeFQ==
X-Gm-Message-State: APjAAAVh3kCQD9pdvJlUjqa2ECmD6U4PgCljDBBy6BrB6nPg2Su3s4cG
	ZmjrfidUo95X9Xm+Anfk02M=
X-Google-Smtp-Source: APXvYqxjtlFE4WmX22tdZVzlQ0LsMM34jEKxTRIM+B6eNRLzpOUJ25zUPa98jv69MbavpUNatMc2jw==
X-Received: by 2002:a17:90a:8043:: with SMTP id e3mr8573372pjw.24.1575545731486;
        Thu, 05 Dec 2019 03:35:31 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:b68c:: with SMTP id c12ls737462pls.6.gmail; Thu, 05
 Dec 2019 03:35:31 -0800 (PST)
X-Received: by 2002:a17:90a:b318:: with SMTP id d24mr6768448pjr.142.1575545731130;
        Thu, 05 Dec 2019 03:35:31 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575545731; cv=none;
        d=google.com; s=arc-20160816;
        b=R64HaN5RMaxHWDzBbBEJ+UIQJLiBo8YH7qAc/+AIZBEY/Rbgz62dEi2JeoexD0Efn7
         GiTRnWozWStukjZAQqfqatciPwt+2OICjletKsNr0AQGX3dlcZszVL7nnsYR3qBSqE7w
         JLYSYEFYbsHjDtnoCR8JIZsnW0B1WG2Zyq+rJ93yywNF44io6Pu7vusnFDr2Ic1CYfAA
         PFJv5yb7COPWchwDv48eoTQlhNqIqINdFccwyvzWKFz00XfH/ViNXj/Jku8awvYH6Kl9
         Gif8Zpltz0uHWlu5fuEvoasJ7uO5zpAi/zewSGKMzWpL7htf3SbbKzvaKo7W1AqJSqKC
         ZZqg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=XFj7/o8CY27u2EP/Ii6IWyV6V/qKCHo8NGPo9OoyP2o=;
        b=WCt/bkmycy1N22eHUSdsMZWUL0XvguNAcmV88CbmHzl/UZlO5h5qFLoJnAZp8XJGSb
         Usn1lXWRhbEt+AIhCC6jvYW3spyq7x075UXtl/i5wksoanGszLfwx+NusLLgN/F2rFtg
         t6VdcmfVs+RnWmMiySjmGeLa3hysgv5gyTze2/BWUYSsMFNzOS6l9gfZFGKpVYPecL7u
         bbSbse2UiEJB6nVmQcGnme9j0lq8kectRQ0wOXNE0re9IXQSQUytggK5RP0FxKSiqD8i
         PgJgRQaSDzWnWHCg4ZIWDwwf4Rv2maSbiTKWrIdMhTkOY1SQgb4eBYCA8u66kaYCB9K5
         4Pqw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=VLVyGXFm;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id f23si233422plr.0.2019.12.05.03.35.31
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 03:35:31 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id 38so3158487qtb.13
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 03:35:31 -0800 (PST)
X-Received: by 2002:ac8:2489:: with SMTP id s9mr7043538qts.257.1575545729972;
 Thu, 05 Dec 2019 03:35:29 -0800 (PST)
MIME-Version: 1.0
References: <0000000000003e640e0598e7abc3@google.com> <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
 <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com> <397ad276-ee2b-3883-9ed4-b5b1a2f8cf67@i-love.sakura.ne.jp>
In-Reply-To: <397ad276-ee2b-3883-9ed4-b5b1a2f8cf67@i-love.sakura.ne.jp>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Dec 2019 12:35:18 +0100
Message-ID: <CACT4Y+YqNtRdUo4pDX8HeNubOJYWNfsqcQs_XueRNLPozw=g-Q@mail.gmail.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>
Cc: Paolo Bonzini <pbonzini@redhat.com>, 
	syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Daniel Thompson <daniel.thompson@linaro.org>, 
	Daniel Vetter <daniel.vetter@ffwll.ch>, DRI <dri-devel@lists.freedesktop.org>, 
	ghalat@redhat.com, Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com, 
	"H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>, 
	"Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=VLVyGXFm;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::842
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

On Thu, Dec 5, 2019 at 11:41 AM Tetsuo Handa
<penguin-kernel@i-love.sakura.ne.jp> wrote:
>
> On 2019/12/05 19:22, Paolo Bonzini wrote:
> > Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
> > backtrace and I get to share syzkaller's joy every time. :)
> >
> > This bisect result is bogus, though Tetsuo found the bug anyway.
> > Perhaps you can exclude commits that only touch architectures other than
> > x86?
> >
>
> It would be nice if coverage functionality can extract filenames in the source
> code and supply the list of filenames as arguments for bisect operation.

What is the criteria for file name extraction? What will bisect
operation do with the set of files?
If you have a feature/improvement request, please file it at:
https://github.com/google/syzkaller/issues/new

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYqNtRdUo4pDX8HeNubOJYWNfsqcQs_XueRNLPozw%3Dg-Q%40mail.gmail.com.
