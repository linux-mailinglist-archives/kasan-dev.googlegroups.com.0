Return-Path: <kasan-dev+bncBDEKVJM7XAHRBN5RWXXAKGQEVFEFW6I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lf1-x13e.google.com (mail-lf1-x13e.google.com [IPv6:2a00:1450:4864:20::13e])
	by mail.lfdr.de (Postfix) with ESMTPS id 99219FC7DB
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 14:38:00 +0100 (CET)
Received: by mail-lf1-x13e.google.com with SMTP id m2sf1968385lfo.20
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 05:38:00 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573738680; cv=pass;
        d=google.com; s=arc-20160816;
        b=I+X7GrbwFX0nkbBtGIv5RFQft8vh9PiKZ6y1wPw9LhbFldzOHIz9HyOv0EmC0Eroj7
         /QTIseqL/O80MKBMrXRjYFjsKDxUWXyA8zlgNbJLl5AQypucppOXsVLA+2iPdv+gfB/v
         iyt+ZLCAJM264n3adpIO///VIu0AGW4Rnd4vxYEkacVuHQ5ZRPi3CZ2BR86YhXklvDz3
         u9eaNi78oI26AhBd0o/1AYtNzI9/+sjeDXCW7wr+RedzxnR6GmYreyz+jEKPkvZdCSH4
         ITxfZZ1hSBYCu0wgjXf3RvFmtyiIHPPj8PG1zuE3XF+T/jKPxkGXaF5f4e3n8mZa8Y7r
         WVVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=znm+Nb1zsGHxzgucxKMD0OS4xq5+RNSVS9tS8epRIOA=;
        b=eKdMfCAQuXgVimQEKqqzRdoHnCQwD9tlTPdBX4xNDi6er+81FjqMbcerXSBPBfNOdx
         BGol/Z16LsrTbP9ApM4ITn0X8z+hYpLnniTJlfEkASka/GZ+Eck+P5+EhhQwr/uhW7xH
         pAAR/uPj72nWDmkkwv8BSURpinz5teg5E+1HvEbiMS0jWSDEGLUesacolkX+MzM2KBX9
         EZFlkb9J0k6OY4ycMJJtgSaf9QJRngRZHwScCTZFoxg3at+qprrfqBZXeb1grx6ZnM7s
         i6+FK4lCfqz4fxsQnSQEYYl5/5nGoYSneVOwU8fRO86Mgq5R+yK/58nE7pJARUT11wf2
         su/w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=znm+Nb1zsGHxzgucxKMD0OS4xq5+RNSVS9tS8epRIOA=;
        b=iSTbO5ceSzDWbyzN2EgWnkEDMtRq0HanN3lIGXIg4NB9XkEb9eUEJxLYKxu6LCJDEx
         Y9Oa4HXNR9DxrQxZtIYeiEgfXJyMRaJqYobsMMnnwpPTjUmUO6rENK0ece9ayUX3uglU
         vd9tsWZrwaTUO8v1na/bUBLzgQrgo+0VnjuD85SmztIWc9otNCjpokoPU0vtFwQEUvIj
         tWcchbmCV8vQaaQC6KRyVh5HGu9T7PjbG4V/FaN3MPVZ14nikAUD8BALDqu5gNW39OkK
         zbA27VKlaJjiqaWjpjhnnEgYRFrK+zsqoO9w8ou3JNyWOha+6pBOAfJa2+U6kRADgZMy
         rMag==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=znm+Nb1zsGHxzgucxKMD0OS4xq5+RNSVS9tS8epRIOA=;
        b=RUam0ePK1AKnUOZFNzOlpsy7Okwww7Tb0/4aTIW1AvdK9WK40727TvZeL3H1F2eQ0S
         2CSB0HSPq71O9z3qQ6fPm5zBhq1m+IhnpQaf3b80md+CMLz1eGhBGvUQ1Mp7L4ceEYDj
         BkEf6UysjWqde/+3cBZdKMlQ8vkIkT+893GCTXpXnRvns0CJTbWaYyn1Itqz0Uyr/90u
         NnQBDWDdrhT8essRkjCMepkqqWCki9hPKZoIY8XewKCn/m15zAlNo3R/vrqU6kd7JPuB
         KZ5SeXrtwoo6AqE9p7O9LQ4/OzZXAecG4qSQvbtM577FsuzimIu/MnBTCgZoDOS8B/ep
         P9Qw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAU98hHnAGVNLFbbhJhoVbExrMdvtOhlVpEvl9tVnUQqR5DTssja
	MdD6nNgnK7/GZNrMDaAqSDI=
X-Google-Smtp-Source: APXvYqyQ0J1sb6/ByyeAovomdyFqsBhCdfiVnPLLsE+VFjQCd4OWhg5y4pNlcViQCZcwW7mfWoUHog==
X-Received: by 2002:a2e:9016:: with SMTP id h22mr6729100ljg.137.1573738679983;
        Thu, 14 Nov 2019 05:37:59 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:5c07:: with SMTP id r7ls955224lfp.2.gmail; Thu, 14 Nov
 2019 05:37:59 -0800 (PST)
X-Received: by 2002:a19:c50f:: with SMTP id w15mr7188538lfe.14.1573738679448;
        Thu, 14 Nov 2019 05:37:59 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573738679; cv=none;
        d=google.com; s=arc-20160816;
        b=ge0fxcvHmaqnb7t7uOhz4USKu3SD36RkIv4ZMK5gcO4cd9Wk6bQAMMeoesZ5xw/ym2
         hGBPUq2Pm5xlfv4vEx8kphOEFWRbFwXEGm+67zYBUPmCVvALgrhprdzh6iVxr4zG0aw9
         yQ4a6fUVAuLwJ5SHhWiupBtVXnKxnzMAPVnhcuKkesB0pV0t8/ehsxLM5B1Y5D2WfUq7
         nE7t6rDl4axlUZYOMoXZdoKF2pLA61n0AYVohbhspVYv6DmoiFVwwgJqezQ+onJusXLo
         DRi7TuAWEIvT+dDrCDkihnBM/yCnmFSrErnTUNYq4OEER6PsRLaxKSCKXCuWhb/wM3GT
         zFKQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=UJUW4Q8qhOPw+VJei7HUE6Eu4DlXLrtM//j3Td/LPPs=;
        b=eQV6oeVBiHnLonwLi8igs45AAKa5k0h4SQ4awOjLyHZ17rihFuPNXiMel77jyjPHzt
         wec1/+WZzEwTMWacZJ0oUfHUzTCrwNXVcMKHyf+sE3DPokoSQruX+0HqYlgpFhPUl0YY
         i/9mGEB56+exb3qyvAFNNtNviByAAaIOgaf/79ZV1YhP9pxwWcWrJMlf1oJBdM4/WAjb
         jGCQtjtzpWd3udMfupUeg9OXS5EIP+M2YsZHkUyXzT9p+BBSSOsCu97Nf4PM5gLi3cEg
         FegUTqG4w/SwwtueEOvwgIUMH+OYAly/ZjMI5eYYvaEhW+wNIRia7SY1OJ/owIs72Yie
         hJSg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [217.72.192.74])
        by gmr-mx.google.com with ESMTPS id t3si217964ljj.1.2019.11.14.05.37.59
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 05:37:59 -0800 (PST)
Received-SPF: neutral (google.com: 217.72.192.74 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=217.72.192.74;
Received: from mail-qt1-f176.google.com ([209.85.160.176]) by
 mrelayeu.kundenserver.de (mreue107 [212.227.15.145]) with ESMTPSA (Nemesis)
 id 1MvJjz-1heFC32RYf-00rHC5; Thu, 14 Nov 2019 14:37:58 +0100
Received: by mail-qt1-f176.google.com with SMTP id r20so6724869qtp.13;
        Thu, 14 Nov 2019 05:37:58 -0800 (PST)
X-Received: by 2002:ac8:2e57:: with SMTP id s23mr8188706qta.204.1573738677418;
 Thu, 14 Nov 2019 05:37:57 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
 <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
 <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com>
 <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com> <CACT4Y+YnaFf+PmhDT5JRpCZ9pqjca6VeyN4PMTPbCt7F9-eFZw@mail.gmail.com>
In-Reply-To: <CACT4Y+YnaFf+PmhDT5JRpCZ9pqjca6VeyN4PMTPbCt7F9-eFZw@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 14 Nov 2019 14:37:41 +0100
X-Gmail-Original-Message-ID: <CAK8P3a1viWDOHPxzvciDt8fPCm3XkbLJxAy1OjtJ_-vuP-86bw@mail.gmail.com>
Message-ID: <CAK8P3a1viWDOHPxzvciDt8fPCm3XkbLJxAy1OjtJ_-vuP-86bw@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	Stephen Boyd <sboyd@kernel.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:g+2scfysbMiRZaL75BVxXurgEnFbMsFMTlR/a6VAULOl4aF6Qpv
 G7qQzudAaWgcoEDL4xZxQmD+TKaX58k97b/qpZ0bUYcKac5o2y4B/ZS8AR28o0GEu5/oZt5
 ISVq7gPeNPbyEgm6zg8UxRXRx7JxPkga30HW6F6BDTmdJb4TIHYgP97syID0r/Y0+fT4J5j
 3B/HWVHhZ4SEiB8PBOs5Q==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:XqfH9Y3uvHo=:jZabtbiuwPGZAxOEwGCD4b
 eVL9ISQBo/vPpnjxiWPAzj6wEv6rs/va8JQ5bL93iqYG3AxcAAA/cz7TkqcN1lLDeV5s7AS85
 6AXPU3YHKsi5m2CKVvIE5xHkcSssk+eCAovA8sqhPX3F3uIkiUQdLZngf/RDJjFD/Duhs1G8M
 jtkfcOhOlB22KiF4SXY2Ud5q/gpL6BXGxdp/FFXn2axWg/mCLPJMxUlbjlzf5daPfE9WYp9Fq
 00M1+QlZbCCFH4XYFt/jZcQLtyXKzeMNpLfyAHULLa3j4n+10/g1UbwDTexeMXb1blmjs2ZQ/
 4LNmZki9xgdUZ+wk4Rv+HXyMVA8sb/APjHYVhN462cb5uAzFRHFznwx9Qt0Q1uiQK72HFQI1f
 YPNdbN58gMhvK/T7FzcqBWhhI37RN7W0IzSMe4/6xzYhUb/cm3ch04q0gOU0aukjcSjA04h+s
 2TvH38rf+xkh5oJ6J0ovuQFekusL5uDD7j3jp4soX5Ix9x7FwIImVbdlRIkjtZwRGloMM2tqW
 2BfM/ffgT4sDTgMJeANvgHfHY+3FoeNCqv7SQ3gbLh4zQwKVaK0R7o0z1JOXFrsTPFQYo8A1g
 sZza0GBJfP6e+99Th5nO2rjh09eA0faT/Orw186XdCtKbj6vNz/kQqQdp7ogLjhkxA0LiPu90
 tumocX8timvwvDbu9a0sKaREHtgCACC0E7sMsm8edtW/71DJ/dR2PB5sS0OUyQN3zZjkSOyG/
 kmJz5K1QpyzEPbrCSx7A1V6KJkn4hCZi70xZwFg+K+CkG5uotYU7iiqemnLpHgocw9+YGZrOu
 Pn9g5q+Jke6crlXtEZ1gF493hEugb7nBrU2Rks13QdL10K7kMPxIb9idw08q1+zbygz6e8cPz
 mZslO3zsq9s23YAej1aw==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 217.72.192.74 is neither permitted nor denied by best guess
 record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
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

On Thu, Nov 14, 2019 at 2:28 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Thu, Nov 14, 2019 at 2:22 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > On Thu, Nov 14, 2019 at 1:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > On Thu, Nov 14, 2019 at 1:42 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > > > >
> > > > > On Thu, 14 Nov 2019, syzbot wrote:
> > > > >
> > > > > From the full console output:
> >
> > > >
> > > > Urgently need +Jann's patch to better explain these things!
> > >
> > > +Arnd, this does not look right:
> > >
> > > commit adde74306a4b05c04dc51f31a08240faf6e97aa9
> > > Author: Arnd Bergmann <arnd@arndb.de>
> > > Date:   Wed Aug 15 20:04:11 2018 +0200
> > >
> > >     y2038: time: avoid timespec usage in settimeofday()
> > > ...
> > >
> > > -               if (!timeval_valid(&user_tv))
> > > +               if (tv->tv_usec > USEC_PER_SEC)
> > >                         return -EINVAL;
> >
> > Thanks for the report!
> >
> > I was checking the wrong variable, fixed now,
> > should push it out to my y2038 branch in a bit.
> >
> >       Arnd
>
>
> This part from the original reporter was lost along the way:
>
> IMPORTANT: if you fix the bug, please add the following tag to the commit:
> Reported-by: syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com
>
> https://github.com/google/syzkaller/blob/master/docs/syzbot.md#rebuilt-treesamended-patches

Is there a recommended way to give credit to sysbot if the bug only
existed briefly in linux-next? Simply listing Reported-by would be wrong
when I fold the fix into my patch, and it also doesn't seem right to
leave it as a separate patch while I'm still rebasing the branch.

      Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a1viWDOHPxzvciDt8fPCm3XkbLJxAy1OjtJ_-vuP-86bw%40mail.gmail.com.
