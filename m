Return-Path: <kasan-dev+bncBCMIZB7QWENRBNOTUPXQKGQEKNP3HSA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x440.google.com (mail-pf1-x440.google.com [IPv6:2607:f8b0:4864:20::440])
	by mail.lfdr.de (Postfix) with ESMTPS id DB479114013
	for <lists+kasan-dev@lfdr.de>; Thu,  5 Dec 2019 12:27:50 +0100 (CET)
Received: by mail-pf1-x440.google.com with SMTP id o71sf1605582pfg.22
        for <lists+kasan-dev@lfdr.de>; Thu, 05 Dec 2019 03:27:50 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1575545269; cv=pass;
        d=google.com; s=arc-20160816;
        b=yT2iUBqFCMAr22ht/olVZdCmPuTa7Z2CL5k/6rWI5sI1OouoLhWnkia8OMncxII/dA
         B/J1NaOJ4Hz9HiJSG5WzEUMjtckPpsOweOO30KtlBo0arw9DLvLj7836DfnKoeMccEz8
         y/RpwlJfwJoe239zPI3sYgjE1gaRLmeu2cY2wufHB8j/PFtazFH+W4JebZziVs0hNHgq
         ImbAovxw3ZwITnwK3xqve9Bb3zzQHNhFklalShlUX+ilsxkTBZPAS5shHUN0MZUruPa0
         XTydMbip9H/aRLre5YXalwLFj1l1bjI1T/akbGALxKOP1keNsOuXyX1OmeKb1/OdS63o
         cfWg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=5yd99prm4HcAKm/+QpT78rvJBPGB+DHUKK5pCRcGmF8=;
        b=bvwkwraLnoH7rNWBjeS6SLOUmM/af1jswzH0qRcLLHIxtRPGbT5K8yCeNBXFDsngKn
         1gEVKfJ9POUJ+aqCTjLvHBRaQngWjFWsZRoliVlAUhrGFCB1LBSmz+HX9LJs1n7wvfCl
         SiQ3Lfisb2SRASPUaLexyH2SNWyDW1olDNG2nyRMsiQ1xgp11FaXWfgCYh/5F0gwYO8f
         UZ5nWxu1OV+9xKESTpqIFdwiPY5CjvZxPL+LBxO53QS1pk+vCnmXXS37CRIVa1yvlLpF
         F14d1++fQl1yctVL+Z6WNPXz4eyTNDwi/eL/1NE1kdBlOzxLDjfa3PWD/mMJXUKwHuN7
         q/xA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HcygGCX6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yd99prm4HcAKm/+QpT78rvJBPGB+DHUKK5pCRcGmF8=;
        b=OcJuWQjNYHLFSygRUPN/uSnzQGw8uCM3C4lIdZ9YcECeZRU4ei3ygZGQV4pn6/0KLQ
         8OyWZ5+HyEUdWlL1V3+WL27PB+894YfIJcBSO1GJoKa7+OUHgNz0LWwlstvB5E/xYFR2
         0fe4Wa5itTPVq6DC5AyNJrmLx98fmEigMsDUSHW/RkYceu7YCQeioksEfS9lv326CkeY
         OzMdXfJ9ztk5Ip8pEIh6p0GQkfmnRPV56Zt/Pj3Eqj8VF4TaT4aki3NXSOKuNWOBjhPg
         gssYtsnvnAJc5w2W9Z3Lh9EWs5PD+i6ClDsoWp/buiT3+vCXb/4NSfzDx3Z+qNFfPwpu
         eM2A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5yd99prm4HcAKm/+QpT78rvJBPGB+DHUKK5pCRcGmF8=;
        b=hUXN6YBfG4D68LL4+vNMQ1x1KcYH7eMhZtXYWTLMQhmz/MqJSfp/0is0GEZ8pFhBD6
         81YGqQo/TH6CAkW7st+dRMIRgt0yTIydWYRIZeg7hnObvtg2/8zEXSO02Bd2s9akA1v/
         tzuhDhz0Vp0NIQ/zW9UDKB6ypRVzYm7yJDIx093xL9r13Sr7pq8lGtbn6kJzU46RFlCq
         ToJCBLxyDuImefVtcX/GmZphEo8yFqjoHMtbo0I+xMWM6OP8rXmGrODGN4/6bQzweDfn
         C7Eb3j8AP2nJXmZDhxEhaJZN6uRyWI1Xm/Dld/51wbqUKQY4xE6zfbCocIyi+bmDmaJu
         Y8sA==
X-Gm-Message-State: APjAAAVSU5rj33uNQSdmbVc7WlSfYH3TNWCk1NIowHp3//7zYoRLdzN7
	Dx9UuZHBZAIHRFNVSKkyIx8=
X-Google-Smtp-Source: APXvYqxrQqrNY/9Tf7Vez8XELohx4XNzaodYcGNgVVTNaVnZzyxRr27yyPFp/B4c3XflNF1D6FU7ug==
X-Received: by 2002:aa7:96b7:: with SMTP id g23mr8210201pfk.108.1575545269201;
        Thu, 05 Dec 2019 03:27:49 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aa7:9d09:: with SMTP id k9ls777692pfp.16.gmail; Thu, 05 Dec
 2019 03:27:48 -0800 (PST)
X-Received: by 2002:a62:1d55:: with SMTP id d82mr8486022pfd.165.1575545268852;
        Thu, 05 Dec 2019 03:27:48 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1575545268; cv=none;
        d=google.com; s=arc-20160816;
        b=PN4z527iMuCwv7VnJXLNWPeRvC0Kv5cBczvj/Rbt70VgHcvIG8NiBwZw+jaJ4YGNnC
         PEiMMBoa6u6c7Obb2Txu4r++G/Uyt6Lc+pa9BCO6WHLba9VtRrtA3Z5UF21NH5U6SOG1
         +CG5TnCwW++Pli1rXAU60hAA+RwiqZthrATkAVT/GIyKJQLH6GXJzgLhNp9DC2ZUkDdh
         DbApmORZmXGaGCNwYq6cGCTqD0+vzrolX4Q0aEo0/WHZ/ar6RebHdIeOyglFFLUu1WyE
         FYpdZlUQ76EhGwpSR9AKK7RGXJm4ViBPDIz6SGqFz9kn4FedOhEILHEaN5JVIfhl9zd8
         4Cng==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=RN4UxK4XX/wD+FOSD/QSslR64zPY0NoSPi7sfqEDTcg=;
        b=EwdGQQ2CjVkEJ66Li8m+2cEDVEXsQgeFqa4+VGAGTa6FcM8XJfv6HJPXuEV20EVS/v
         uld+wa1AO263hwFsqfMPDK7S4D3tJ+vG6HnhMXBY3vkupfHM/jl6lKFapF3eXXaDfMmX
         9ADZBmJM95nTB1KnTi8dF5aY7fRol7s7FLKeTSioc8ZOLDNxHkT9+T2+nwrm0eh//qVn
         xQqPg1VACYtEe2Q0NwxDlTOcrPBE36Yw3kjY45Y4vYmCMswJDTT3T9eTQHFSjRCRWiZU
         KIXVAiS9IA/pPKk07H1Ro6V9fh2RJi/nmbckU4BHBvQBbggAcPkS3f54HiKgy34JZrCl
         JUyw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=HcygGCX6;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qv1-xf44.google.com (mail-qv1-xf44.google.com. [2607:f8b0:4864:20::f44])
        by gmr-mx.google.com with ESMTPS id w2si512466pgt.2.2019.12.05.03.27.48
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 05 Dec 2019 03:27:48 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44 as permitted sender) client-ip=2607:f8b0:4864:20::f44;
Received: by mail-qv1-xf44.google.com with SMTP id p2so1122907qvo.10
        for <kasan-dev@googlegroups.com>; Thu, 05 Dec 2019 03:27:48 -0800 (PST)
X-Received: by 2002:a0c:f8d1:: with SMTP id h17mr7099085qvo.80.1575545267533;
 Thu, 05 Dec 2019 03:27:47 -0800 (PST)
MIME-Version: 1.0
References: <0000000000003e640e0598e7abc3@google.com> <41c082f5-5d22-d398-3bdd-3f4bf69d7ea3@redhat.com>
 <CACT4Y+bCHOCLYF+TW062n8+tqfK9vizaRvyjUXNPdneciq0Ahg@mail.gmail.com>
 <f4db22f2-53a3-68ed-0f85-9f4541530f5d@redhat.com> <CACT4Y+ZHCmTu4tdfP+iCswU3r6+_NBM9M-pAZEypVSZ9DEq3TQ@mail.gmail.com>
 <e03140c6-8ff5-9abb-1af6-17a5f68d1829@redhat.com>
In-Reply-To: <e03140c6-8ff5-9abb-1af6-17a5f68d1829@redhat.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 5 Dec 2019 12:27:35 +0100
Message-ID: <CACT4Y+YopHoCFDRHCE6brnWfHb5YUsTJS1Mc+58GgO8CDEcgHQ@mail.gmail.com>
Subject: Re: KASAN: slab-out-of-bounds Read in fbcon_get_font
To: Paolo Bonzini <pbonzini@redhat.com>
Cc: syzbot <syzbot+4455ca3b3291de891abc@syzkaller.appspotmail.com>, 
	Andrey Ryabinin <aryabinin@virtuozzo.com>, 
	Bartlomiej Zolnierkiewicz <b.zolnierkie@samsung.com>, Daniel Thompson <daniel.thompson@linaro.org>, 
	Daniel Vetter <daniel.vetter@ffwll.ch>, DRI <dri-devel@lists.freedesktop.org>, 
	ghalat@redhat.com, Gleb Natapov <gleb@kernel.org>, gwshan@linux.vnet.ibm.com, 
	"H. Peter Anvin" <hpa@zytor.com>, James Morris <jmorris@namei.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, KVM list <kvm@vger.kernel.org>, 
	Linux Fbdev development list <linux-fbdev@vger.kernel.org>, LKML <linux-kernel@vger.kernel.org>, 
	linux-security-module <linux-security-module@vger.kernel.org>, 
	Maarten Lankhorst <maarten.lankhorst@linux.intel.com>, Ingo Molnar <mingo@redhat.com>, 
	Michael Ellerman <mpe@ellerman.id.au>, Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	Russell Currey <ruscur@russell.cc>, Sam Ravnborg <sam@ravnborg.org>, 
	"Serge E. Hallyn" <serge@hallyn.com>, stewart@linux.vnet.ibm.com, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>, Kentaro Takeda <takedakn@nttdata.co.jp>, 
	Thomas Gleixner <tglx@linutronix.de>, "the arch/x86 maintainers" <x86@kernel.org>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=HcygGCX6;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::f44
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

On Thu, Dec 5, 2019 at 11:53 AM Paolo Bonzini <pbonzini@redhat.com> wrote:
>
> On 05/12/19 11:31, Dmitry Vyukov wrote:
> >> Ah, and because the machine is a KVM guest, kvm_wait appears in a lot of
> >> backtrace and I get to share syzkaller's joy every time. :)
> > I don't see any mention of "kvm" in the crash report.
>
> It's there in the stack trace, not sure if this is what triggered my Cc:
>
>  [<ffffffff810c7c3a>] kvm_wait+0xca/0xe0 arch/x86/kernel/kvm.c:612
>
> Paolo


Oh, you mean the final bisection crash. Indeed it contains a kvm frame
and it turns out to be a bug in syzkaller code that indeed
misattributed it to kvm instead of netfilter.
Should be fixed now, you may read the commit message for details:
https://github.com/google/syzkaller/commit/4fb74474cf0af2126be3a8989d770c3947ae9478

Overall this "making sense out of kernel output" task is the ultimate
insanity, you may skim through this file to get a taste of amount of
hardcoding and special corner cases that need to be handled:
https://github.com/google/syzkaller/blob/master/pkg/report/linux.go
And this is never done, such "exception from exception corner case"
things pop up every week. There is always something to shuffle and
tune. It only keeps functioning due to 500+ test cases for all
possible insane kernel outputs:
https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/report
https://github.com/google/syzkaller/tree/master/pkg/report/testdata/linux/guilty

So thanks for persisting and questioning! We are getting better with
each new test.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BYopHoCFDRHCE6brnWfHb5YUsTJS1Mc%2B58GgO8CDEcgHQ%40mail.gmail.com.
