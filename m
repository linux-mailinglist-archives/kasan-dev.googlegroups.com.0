Return-Path: <kasan-dev+bncBCMIZB7QWENRBO6E3PYAKGQERC2RIBA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x339.google.com (mail-ot1-x339.google.com [IPv6:2607:f8b0:4864:20::339])
	by mail.lfdr.de (Postfix) with ESMTPS id C3042135434
	for <lists+kasan-dev@lfdr.de>; Thu,  9 Jan 2020 09:20:13 +0100 (CET)
Received: by mail-ot1-x339.google.com with SMTP id f25sf3282022otq.15
        for <lists+kasan-dev@lfdr.de>; Thu, 09 Jan 2020 00:20:13 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1578558012; cv=pass;
        d=google.com; s=arc-20160816;
        b=WbvC4Qt55qoYlk0BPL8GS2SWVCKscfs6wvb0kahkCKcuiFPTCppM5uEbYeyMclE83c
         MxIig/BWEu5d4tPnTvFTRhv0weobhGmAXRD2z2AMtV8OAgihddOLN8V2DkUm0ysYjIdN
         RiTzxAeCgRM/NfJ8s41LqiKI0i1hc41PyovY/Nspq7CejaT63pj2UmlQllSTD56vCdaM
         Lm9774X82w44BLYbCIzU4cpRMb8LeceaeNLWmUn4wKale6systvOz6DYxNum+pP5tyvr
         jT76Dr6TRNsf7CjEVBGmVJx4WInggwjPqQX+j0mXB0oNr9W2xHxPL4JWghQzuYZuJ3Rf
         8+VA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:cc:to:subject:message-id
         :date:from:in-reply-to:references:mime-version:dkim-signature;
        bh=fRL0dbxiEDmmvvVFi8MMLPAR79ruygH1xqK0qkmtIUI=;
        b=mtsSuqOP2HV0V/0i19HYYTQ4T52peOBMCKAvhgggZ9mCE7N2fL/9elZEdwx5lKw8A/
         cwvnsuIj0r8+lE/Kh7WsfMal5Fw4f3ymh9kHgOVsD8vhy5p/szK6Y+NjcghuoE7nznHH
         Vd2EPFJPaaPPRJives8vf7EnBstcHhkn2CgDnVRh7Lg+n66EINmtsZ1PiIdKmfQdqeJL
         CkW6rBm9O2dSN8KIwmfVEckuminku1bYofyPtHpqfKhYnbw20SYfoWWF3AHbcHaZs2ij
         Tqq/xPTO6u0dhUaQOY+THcB0ZhwL+z36CDWivIiXU6tjMWbgimEk9tdopUb8OcOgm2xF
         rDgg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KdgOUrwo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fRL0dbxiEDmmvvVFi8MMLPAR79ruygH1xqK0qkmtIUI=;
        b=aRYLnkI/t7q3FHFqvJ7DqQzV35AZd8gCGntE7Y5jF5f4bTscFVa+wD5t29pRXRny8A
         PDQSrHMgHAcfgNHSMvdHSCiNK2AuVweh3l/9QTI760xXTMDcnPnhWkNDyfWl3wCrtSVu
         X50y3iC5dVXaicuaGTdXzkcZ5Vvo2tOpeW6QdCD5uaBwfqH/dQfB1cC3CO3Q4N7U97Yx
         EKibdgSny6T9Ply//6TcX8O6Oc+D9zd9V4yi4MQSmXd8pT9lsRBtL3quX1N9USg7/uVW
         hjbwhxzSSMq50g9mipZ4VV7Z5Bugsl769NFMtqsAlnZtnZ+gtNbwpOBK7f59T1OvOYKA
         oHdQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=fRL0dbxiEDmmvvVFi8MMLPAR79ruygH1xqK0qkmtIUI=;
        b=XthNce6kXaUspIcZ7s+GfW/9nd3NI0kfpcCEysXGLJp0ER3ubIGm/oXN3EaljP15LC
         AyLE1vpRpAVXxrurcs9DgtmNZeSpBNbtNlTnFwPf6NG0INg4P5HJqPNYqP94gO13Xi41
         Op1yWTOXs6zdOsBigEahQuQzIIVcDBwoarUPUczngOPOBrDzCXT0fnznOSFjOW0ZYJ/S
         MWAFcEZgDQj97NKZ7pMFG5MBHBHTtSP1qpI156aVNdLXj655zeNY6GSMlh+bfsFEsshm
         7Z/7blLsVv+Yofo72iJauGNCnzZ99913nJYFDKzPXvU33e7HqTjUMY9DfJl/rdTvqjE9
         /gGg==
X-Gm-Message-State: APjAAAVJ+3EK1X0EM0ouLbVYcTVH2xL89o0z7sR0LzB99VwHQA7EGaLj
	4F0BBDPzfJ8Pb2In44++SEU=
X-Google-Smtp-Source: APXvYqwGUdXGB9hRngfPDAOVE9671HRwaVd+/uGLkquKWeS+GaWSj2/qVbsmFGGEPvienUy9VAmf6w==
X-Received: by 2002:aca:f305:: with SMTP id r5mr2323675oih.174.1578558012017;
        Thu, 09 Jan 2020 00:20:12 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a9d:5a87:: with SMTP id w7ls262973oth.1.gmail; Thu, 09 Jan
 2020 00:20:11 -0800 (PST)
X-Received: by 2002:a9d:6758:: with SMTP id w24mr7892644otm.155.1578558011539;
        Thu, 09 Jan 2020 00:20:11 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1578558011; cv=none;
        d=google.com; s=arc-20160816;
        b=PCdlPT3cfz0CicvF4qau6mpctE2ajct37BbFnEUpZKtuPfGvzk+jAWzoLJdqumO7O3
         bytZjVFM7DkmcXMFBG7vWJ9E2+ksp7W4NPHcnFCT4YGee0frs/G9uP3fzYCjZgldmT7R
         MMPgz0y60kLFiBRuWIc93ghQ3QoEyby9Fbh9w04ejKk6nIgL5a+v14VtRXvaHj4faUcD
         xh0tjFRRdZbq+11od73wlsJZ9CHFKZBqgNXSZkRMsu1nsX6Lke7by0qpAQiaKoLmOzhz
         3drCnAYP8hFnSHhPAlRS8nVtKqWcgWKrBidQCOwB1Ik64Plv7rMKZBFQF/IXnQyYjExi
         rGTA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=nntsi3ZIZ4YTnCqpslNwLZBauzhg9rC3/Kr5lCbJGLM=;
        b=o7c4NG22ZZhI2AbXlspfwY53RwNI1CrXXqz3XwmTGa1BopmqC3RnUlBlDtX1DgE3Wi
         IMzYuzPm6FUnWPruuOh7zr10hQTF/9jumGOWv1mN/eHTBrvqPBr+q/Fd51V3Kxjj0W0h
         OKfA7qbBd80sPP0UQdZ6cyoWz6pG4QJ5uwx4i5+GVmoaR8fXqDB2zaICMtxLUggsJhhj
         hc49UELhoREEgaMZuJ5WaM2HJgNxgizGpF++DQCHx1+0mVHtqgpwTTrmy7jZs9khYhoc
         2TpDANXTGTTGLn6AyJwiZIdpZyeU4UmLH0rVdsnaMzKnpgHdilwIJf/TPA4k3U6s2BRA
         6p/A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=KdgOUrwo;
       spf=pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) smtp.mailfrom=dvyukov@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-qk1-x741.google.com (mail-qk1-x741.google.com. [2607:f8b0:4864:20::741])
        by gmr-mx.google.com with ESMTPS id w63si249733oif.2.2020.01.09.00.20.11
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 09 Jan 2020 00:20:11 -0800 (PST)
Received-SPF: pass (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741 as permitted sender) client-ip=2607:f8b0:4864:20::741;
Received: by mail-qk1-x741.google.com with SMTP id c16so5205830qko.6
        for <kasan-dev@googlegroups.com>; Thu, 09 Jan 2020 00:20:11 -0800 (PST)
X-Received: by 2002:a37:e312:: with SMTP id y18mr8541800qki.250.1578558008734;
 Thu, 09 Jan 2020 00:20:08 -0800 (PST)
MIME-Version: 1.0
References: <00000000000036decf0598c8762e@google.com> <CACT4Y+YVMUxeLcFMray9n0+cXbVibj5X347LZr8YgvjN5nC8pw@mail.gmail.com>
 <CACT4Y+asdED7tYv462Ui2OhQVKXVUnC+=fumXR3qM1A4d6AvOQ@mail.gmail.com>
 <f7758e0a-a157-56a2-287e-3d4452d72e00@schaufler-ca.com> <87a787ekd0.fsf@dja-thinkpad.axtens.net>
 <87h81zax74.fsf@dja-thinkpad.axtens.net> <CACT4Y+b+Vx1FeCmhMAYq-g3ObHdMPOsWxouyXXUr7S5OjNiVGQ@mail.gmail.com>
 <0b60c93e-a967-ecac-07e7-67aea1a0208e@I-love.SAKURA.ne.jp> <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com>
In-Reply-To: <6d009462-74d9-96e9-ab3f-396842a58011@schaufler-ca.com>
From: "'Dmitry Vyukov' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Thu, 9 Jan 2020 09:19:57 +0100
Message-ID: <CACT4Y+bURugCpLm5TG37-7voFEeEoXo_Gb=3sy75_RELZotXHw@mail.gmail.com>
Subject: Re: INFO: rcu detected stall in sys_kill
To: Casey Schaufler <casey@schaufler-ca.com>
Cc: Tetsuo Handa <penguin-kernel@i-love.sakura.ne.jp>, 
	syzbot <syzbot+de8d933e7d153aa0c1bb@syzkaller.appspotmail.com>, 
	kasan-dev <kasan-dev@googlegroups.com>, Andrew Morton <akpm@linux-foundation.org>, 
	LKML <linux-kernel@vger.kernel.org>, 
	syzkaller-bugs <syzkaller-bugs@googlegroups.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: dvyukov@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=KdgOUrwo;       spf=pass
 (google.com: domain of dvyukov@google.com designates 2607:f8b0:4864:20::741
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

On Wed, Jan 8, 2020 at 6:19 PM Casey Schaufler <casey@schaufler-ca.com> wrote:
>
> On 1/8/2020 2:25 AM, Tetsuo Handa wrote:
> > On 2020/01/08 15:20, Dmitry Vyukov wrote:
> >> I temporarily re-enabled smack instance and it produced another 50
> >> stalls all over the kernel, and now keeps spewing a dozen every hour.
>
> Do I have to be using clang to test this? I'm setting up to work on this,
> and don't want to waste time using my current tool chain if the problem
> is clang specific.

Humm, interesting. Initially I was going to say that most likely it's
not clang-related. Bug smack instance is actually the only one that
uses clang as well (except for KMSAN of course). So maybe it's indeed
clang-related rather than smack-related. Let me try to build a kernel
with clang.

> > Since we can get stall reports rather easily, can we try modifying
> > kernel command line (e.g. lsm=smack) and/or kernel config (e.g. no kasan) ?
> >
> >> I've mailed 3 new samples, you can see them here:
> >> https://syzkaller.appspot.com/bug?extid=de8d933e7d153aa0c1bb
> >>
> >> The config is provided, command line args are here:
> >> https://github.com/google/syzkaller/blob/master/dashboard/config/upstream-smack.cmdline
> >> Some non-default sysctls that syzbot sets are here:
> >> https://github.com/google/syzkaller/blob/master/dashboard/config/upstream.sysctl
> >> Image can be downloaded from here:
> >> https://github.com/google/syzkaller/blob/master/docs/syzbot.md#crash-does-not-reproduce
> >> syzbot uses GCE VMs with 2 CPUs and 7.5GB memory, but this does not
> >> look to be virtualization-related (?) so probably should reproduce in
> >> qemu too.
> > Is it possible to add instance for linux-next.git that uses these configs?
> > If yes, we could try adding some debug printk() under CONFIG_DEBUG_AID_FOR_SYZBOT=y .

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CACT4Y%2BbURugCpLm5TG37-7voFEeEoXo_Gb%3D3sy75_RELZotXHw%40mail.gmail.com.
