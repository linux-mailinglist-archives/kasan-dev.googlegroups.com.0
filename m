Return-Path: <kasan-dev+bncBCQPF57GUQHBBOUBZX4QKGQEPABPRWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb38.google.com (mail-yb1-xb38.google.com [IPv6:2607:f8b0:4864:20::b38])
	by mail.lfdr.de (Postfix) with ESMTPS id 8D06D242392
	for <lists+kasan-dev@lfdr.de>; Wed, 12 Aug 2020 03:07:07 +0200 (CEST)
Received: by mail-yb1-xb38.google.com with SMTP id x184sf994730ybx.10
        for <lists+kasan-dev@lfdr.de>; Tue, 11 Aug 2020 18:07:07 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1597194426; cv=pass;
        d=google.com; s=arc-20160816;
        b=ojBPNWLBFphCNKHd/1GqAa43PskNQfOhn/Mi1GcH6fkkLkx0ghwkQOlkGiVIEZX0zR
         370Tej/PSEK9qWPYGQfO/U8fjad6gn9K4oUhMiTC8ZRkzWrRcNxp1rCLog4BxSjsENYc
         MKlcpOA1ANi3ccO4PHLWg/qQcmHKTDBIo18k9Kyw2NqFkUEXylgWQxywyzPGUq5/VgtL
         X22rox90jFaHvtlHj/03BDwth/ytsboeQNHec6OGdG+dvPdW1faS2QUdwlYPQwzzO8Bf
         ZcoXfsHbU62ZTFzGxwifmb0ZBh86pxYzmmbBRIwn316ScIgj+nQMGJp5r/3wwGL/xZ+r
         pVNg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:from:subject:message-id
         :in-reply-to:date:mime-version:sender:dkim-signature;
        bh=kGBoInuTqCYUmxPRWgRbrRtEP9LbTT2lPgXkzv5dB3I=;
        b=fMHpgM9O26zTACEi1PsqDjYFlbIRGckBxPTu6KLfgmSp+U96aNkGVJMBBbtYSbYrvD
         unhn4sx60X44Jp9H+R1h224AjZXiTJxoADcohj1MLGXZgYtMxvqjk+sctPi7E2wv77eX
         tImQZkyd5xw3SnPQU+6qPLDa6kmlTOCSid2sYhzdG3B1dSvfkrDBL5qPkdOyI61pj/cg
         l67x+kJlHaOhunh1ts41vO3XtdxAxZnl5hDk1SB5EHSIcZXDI4w+v+SHz76vFjZonvHg
         zRglqeCc4aNsDnrL0miktE3HQ9MkOxayNxXnqfFQQlwiUd3iI6IdFTwZHvQsYsF4bVQR
         zAYA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of 3uuazxwkbaag067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=3uUAzXwkbAAg067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:date:in-reply-to:message-id:subject:from:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kGBoInuTqCYUmxPRWgRbrRtEP9LbTT2lPgXkzv5dB3I=;
        b=IO0CY10aSwYE1P4ZD3xN29wT4rimwbQ+r3YLpJporjhDP2m6AZE5Lq8fbPGTjwucLl
         bcdUpIHTd0jiYLkxNzuvt9XJCtdSpY39gdfBaLgPZT/sKeRqxT9hBZ1dHH0LOlfLH8fI
         USx7aThSHOAT0GEexjwTvxuYfYpWVrMdjPw0njOh6AOQVxMAU8Qg7XJdUqHCcBXhz8q3
         hv5WJ33F9h6hwkQEfrRuIwE+VFYtFBodIIiBUMPBl/x8oKZGc+GEXnzE2zrjvh0zJaht
         pz+iVOUn5Tb83JRiSDvX7+33x/g/mbVfHZr9Eiq5954NumArJwVza4n5JuFn2/UZGvnS
         +FsA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:date:in-reply-to:message-id
         :subject:from:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kGBoInuTqCYUmxPRWgRbrRtEP9LbTT2lPgXkzv5dB3I=;
        b=R6JareRgeVS+cXPPSnBrt7pQm5F84IroUJD9hhYPrcaWRHxhXcnVzZ6govBrgoDo/U
         na+wnL8zWt4hr8PnlFN9t/OjAmUlSjs8H3n+ZynlbcrFTAZ7brKwvFRMc3qw5a4bWrxQ
         ewIN1UXS+naYBBusT2clakhrj1icDlPLqlJtrjfIBJ0pw1KTOACR3V6bEFoeqHlVdQW9
         QY6T4P04AftDjF/TdBWu3rDcSMmyDYygvn7Q/++ObvqXe5RZZZbbbWivNygfPev4ogU9
         ymFvRHHg5WpJYV1ToYPR162yC4f+lCIRHlvgC32EnteA1AxEPiwIIWMGv3XNdI/sL+T/
         gjnA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531MkGbtMHPQmG12iTSpRNWWNX3DTIhRhNQrzPRKsW2KC6P6YGiA
	vC9StIUUbwPSxItdEfdFuKA=
X-Google-Smtp-Source: ABdhPJxsntfrQ4mwfIaRzPtoCArMZc8eDM4AvB7fz5NPDxp/as2SmUU+FQ2A46x1JXKUffDih8WXXw==
X-Received: by 2002:a25:d78c:: with SMTP id o134mr49608490ybg.167.1597194426318;
        Tue, 11 Aug 2020 18:07:06 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5b:b0d:: with SMTP id z13ls228816ybp.8.gmail; Tue, 11 Aug
 2020 18:07:05 -0700 (PDT)
X-Received: by 2002:a25:e74f:: with SMTP id e76mr52318193ybh.337.1597194425840;
        Tue, 11 Aug 2020 18:07:05 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1597194425; cv=none;
        d=google.com; s=arc-20160816;
        b=u9A1+5APH4Y3qdL86OCNZADfAJmS1I6+Fwh68YIP+fEYnbqV/0dJ3EbgkCzFXFIIyW
         TWl+A8YfLwyEbgKgTnZfCQ2AaOykOpHk/hQDmDEs6/nL6NMFZOKitEORpoAc/+z0GEeB
         6nzLI3Jam8/f9/sAVS2Ap/4nePkp/OR2uW0uNKrAksxRvYeZMfSv4VCS75kXSGzRhfei
         odBJI/b7scpt38TeWRSdo1FXvCURj19b5MV1+9lEoy6M4O0+DvFFdUfYCRkrDNYxf+TE
         PS7r1fo0h5hX/HqbSimN0bYSvLXLLyZnV0qug+RyRY1UaFOLfnpvs2SNRA22VecDl4QX
         L6DA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:from:subject:message-id:in-reply-to:date:mime-version;
        bh=X3NiX6nVSgp11EpijWT3pX7H1MOgqhCnBt3mOeEwKPI=;
        b=PsKKE2NyGgwGSLHttvI0aY+C1D+RfZBw7pA21iujqKrpXL/s9bSzkyXTlhUAi7AV5N
         tX1+qd1nHMBWqXdy27+u23519e6QR/bQNu6p5+lO1zQMMjoV4LdIbE7N1OTMUppuWHd3
         NsZ/xdzdPsoczNo0XVOO6lxLRtYHXcwnFBN2wp2NYGpkpUIR0iIPU8BOSnyIYdd6qk/T
         jPLRUs1o5pk5CzkRqEjfNY5Ces2BmlYZVAi5F2SmjCEdUtQa5358LOwf2W61YiaWwOmJ
         Xsnpubcq6hbiLjIO65bKq80DwxvE/kWq0kuISnTN5Efsimv3GOE3fusxOYD7aGhVK2Pj
         Nzkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of 3uuazxwkbaag067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) smtp.mailfrom=3uUAzXwkbAAg067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
Received: from mail-il1-f197.google.com (mail-il1-f197.google.com. [209.85.166.197])
        by gmr-mx.google.com with ESMTPS id o14si45228ybm.5.2020.08.11.18.07.05
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 11 Aug 2020 18:07:05 -0700 (PDT)
Received-SPF: pass (google.com: domain of 3uuazxwkbaag067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com designates 209.85.166.197 as permitted sender) client-ip=209.85.166.197;
Received: by mail-il1-f197.google.com with SMTP id 65so620842ilb.12
        for <kasan-dev@googlegroups.com>; Tue, 11 Aug 2020 18:07:05 -0700 (PDT)
MIME-Version: 1.0
X-Received: by 2002:a92:bbc6:: with SMTP id x67mr26231257ilk.235.1597194425363;
 Tue, 11 Aug 2020 18:07:05 -0700 (PDT)
Date: Tue, 11 Aug 2020 18:07:05 -0700
In-Reply-To: <000000000000b6b450059870d703@google.com>
X-Google-Appengine-App-Id: s~syzkaller
Message-ID: <0000000000005c72d405aca3ce17@google.com>
Subject: Re: KASAN: global-out-of-bounds Read in precalculate_color
From: syzbot <syzbot+02d9172bf4c43104cd70@syzkaller.appspotmail.com>
To: a.darwish@linutronix.de, akpm@linux-foundation.org, bsegall@google.com, 
	changbin.du@intel.com, clang-built-linux@googlegroups.com, 
	davem@davemloft.net, dietmar.eggemann@arm.com, dvyukov@google.com, 
	elver@google.com, ericvh@gmail.com, hverkuil-cisco@xs4all.nl, 
	jpa@git.mail.kapsi.fi, juri.lelli@redhat.com, kasan-dev@googlegroups.com, 
	keescook@chromium.org, linux-kbuild@vger.kernel.org, 
	linux-kernel@vger.kernel.org, linux-media@vger.kernel.org, 
	linux-sparse@vger.kernel.org, luc.vanoostenryck@gmail.com, lucho@ionkov.net, 
	mark.rutland@arm.com, masahiroy@kernel.org, mchehab@kernel.org, 
	mgorman@suse.de, mhiramat@kernel.org, michal.lkml@markovi.net, 
	miguel.ojeda.sandonis@gmail.com, mingo@redhat.com, netdev@vger.kernel.org, 
	paulmck@kernel.org, peterz@infradead.org, rminnich@sandia.gov, 
	rostedt@goodmis.org, rppt@kernel.org, samitolvanen@google.com, 
	syzkaller-bugs@googlegroups.com, tglx@linutronix.de, 
	v9fs-developer@lists.sourceforge.net, vincent.guittot@linaro.org, 
	viro@zeniv.linux.org.uk, vivek.kasireddy@intel.com, will@kernel.org, 
	yepeilin.cs@gmail.com
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: syzbot@syzkaller.appspotmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of 3uuazxwkbaag067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com
 designates 209.85.166.197 as permitted sender) smtp.mailfrom=3uUAzXwkbAAg067sittmzixxql.owwotm20mzkwv1mv1.kwu@m3kw2wvrgufz5godrsrytgd7.apphosting.bounces.google.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE) header.from=appspotmail.com
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

syzbot suspects this issue was fixed by commit:

commit dfd402a4c4baae42398ce9180ff424d589b8bffc
Author: Marco Elver <elver@google.com>
Date:   Thu Nov 14 18:02:54 2019 +0000

    kcsan: Add Kernel Concurrency Sanitizer infrastructure

bisection log:  https://syzkaller.appspot.com/x/bisect.txt?x=13eb65d6900000
start commit:   46cf053e Linux 5.5-rc3
git tree:       upstream
kernel config:  https://syzkaller.appspot.com/x/.config?x=ed9d672709340e35
dashboard link: https://syzkaller.appspot.com/bug?extid=02d9172bf4c43104cd70
syz repro:      https://syzkaller.appspot.com/x/repro.syz?x=147e5ac1e00000
C reproducer:   https://syzkaller.appspot.com/x/repro.c?x=14b49e71e00000

If the result looks correct, please mark the issue as fixed by replying with:

#syz fix: kcsan: Add Kernel Concurrency Sanitizer infrastructure

For information about bisection process see: https://goo.gl/tpsmEJ#bisection

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/0000000000005c72d405aca3ce17%40google.com.
