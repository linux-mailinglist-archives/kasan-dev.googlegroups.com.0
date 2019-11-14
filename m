Return-Path: <kasan-dev+bncBDEKVJM7XAHRB2VXWXXAKGQE4XTR2OA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-wr1-x43c.google.com (mail-wr1-x43c.google.com [IPv6:2a00:1450:4864:20::43c])
	by mail.lfdr.de (Postfix) with ESMTPS id DDD56FC823
	for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 14:51:38 +0100 (CET)
Received: by mail-wr1-x43c.google.com with SMTP id l3sf4467816wrx.21
        for <lists+kasan-dev@lfdr.de>; Thu, 14 Nov 2019 05:51:38 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1573739498; cv=pass;
        d=google.com; s=arc-20160816;
        b=YWN12+oQTKwfKdDpxRtKovcpKlpSCeI8nLJE4ubs/GuQElgTSnsJiNECzrpzO3cw6l
         hWiVBxyqqFhnm3apELEultfl7peDvJvOO6cYSZ/CwVJlwM/dOcaSS4QEZbwP4SNlMFsA
         KtcMmgLQ2QJUg7v/DwUyQD9pP5pn7qELbfxFCzZQRj5VyFbwu0hjj9fjl9rJSC06HxoR
         HqaNp0n/jc0SWiTtLjsQYQONF719HSoUkVxACPAzF+exP4jYixWTvpJQpdfwblnXEa9m
         xdiko3gIMirTtXoKQrZ9OL7Tjue2v/Z8SHb8XU2kI7++Wmw+pbRumxUIyOInSU+lKlSC
         vR4A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature;
        bh=uZ1HQu8DEOGXuNU9zXNQs8jQqkNIJFOGosVvhsX11do=;
        b=k6AeZB3a8CPX+Z6LbkO+CQbviKXSoA5ynFw/P9Bo0natOCtTyVBhcg5gEqfH97vOxI
         eVYiqHsmi34vd24ak5Q+h97KBEdoRcKo/dHNWsOCqTEpEmuxiqYz1mkSby48U3ekphsR
         yfBNDXi1//E7Oo+9KBAIF0NYzbJNdubCEJPTKsPTWrgQHAT5rEu4UuJFZgXRWa6jm9hq
         7qhizaw/LJRwFLd0pZ6u2VIsLBse/Zugxy9BbI/qGG07PgqdP3iQ+eiwpVu/TT96jqAm
         aDc/7ugzpbbn94otoKb0D6nQ4Fu82DXyov0PBLkJvDuvzSmCTd3CJ0saGhfnyuo1kDn7
         t4NA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uZ1HQu8DEOGXuNU9zXNQs8jQqkNIJFOGosVvhsX11do=;
        b=g8Tb7jSHFOo6iH14jga7VCtXVGStJDkt5oYZ+37CIayKX75oCz77tgf+XqYDaxBd1j
         p25NT1nguF6dsi2t8EArhXnOKQNUEuv3M03aIyblR187r6w9q0ci0fpmsDA63rdIBDqR
         YsUZ2MKjoFiMRQHWHYXZeaWidh/E3QBZYqsre6OPFAEBmd6aildnbVTW5mAngJ2Id0Ri
         ZvqfRuP0lPzj50Wz4180vMZu0be5p8FyYFj87L7KQmV9ttSbZrqTzsPRzAoY1jv31qs5
         Ets1ob6fu6RoEu5xcj94Q/Q0XpmML0P1DeuXoTejFlr14d5R7LVkcVuFnBauGnigpmd/
         Fp0A==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=uZ1HQu8DEOGXuNU9zXNQs8jQqkNIJFOGosVvhsX11do=;
        b=guGYDq5pNXulICuUI0+0tVv1BZWoLV/A5ckhwQfo7H8d3xuG989TiVVyuDuez5NzBS
         5Vfc3rt0h6FbhXi1n1rq6aXclzuzUP/7rZs425RUIZHvdkyqFhF3pQCs+CPNSlS1OLci
         kprsiQOyY/8qdWR0bC0HcLKLP2Kj2lOoFkEyqF/xp+PPokOyoc7CtfLCIK3ip77E0hRr
         /n94Jpuw40Fb+xgUd/6u3qSll+7Y2LU8xzceuEKlsCFSnEnR/ItA9qRBRZCNYqN6Wvv0
         NYAN5vrNd/ft7Gk16KB+9Nb9xNvgpKeH07fmWUGKSpBvWfPnCIGRwlEJPEL2fWvHvzNH
         CflQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUlxDOAwQ2mbNmeUiTbnqdxZWy/gapvIfTS4d1jWSR8RNy0PFkj
	qBgxzR42je1cGwWgUqylvt8=
X-Google-Smtp-Source: APXvYqy/M97JQx+ZElLuSttejr077M62N/2co3Wc2S+PgWisQnLH6i5u2ig/uADrUDF6CZ0ZnB5LWw==
X-Received: by 2002:a1c:6745:: with SMTP id b66mr7880128wmc.30.1573739498574;
        Thu, 14 Nov 2019 05:51:38 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a5d:4050:: with SMTP id w16ls8113320wrp.13.gmail; Thu, 14
 Nov 2019 05:51:38 -0800 (PST)
X-Received: by 2002:adf:ee92:: with SMTP id b18mr8824887wro.346.1573739497984;
        Thu, 14 Nov 2019 05:51:37 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1573739497; cv=none;
        d=google.com; s=arc-20160816;
        b=jxPl+gqGIrXCBdC4rPyF6Bwy24q5qxuGGcqvEYf0cov0gIES+FJp9+XtDwiokiowlG
         RbkMSw8Oh40XyPdXhqTB6adEwJJGdl79OsSl0zHxHHpvnkckrgewNv51IzF6V8giPQMp
         T2cGHG6+O3FhR1lhAUsScOvjs6sab0AbVL3pXXyeB09zAy+iIewMY+YqrEEOOhQ6hpbb
         iW8GSlfiCKLLZpGdJx3LWsASd5PsBiEGhE54vRqbT6IRasBaf7MdElnNBKhVkMfdAerf
         gND1WYv3HDmRYAjQDC9K0ASb5ZcsoozoGQ3MAafFI54FJiYSc5NiGktpZ8GZdjLIgl0L
         DcQw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version;
        bh=0SE2OzbRBXVTV6TaqLSLK+lt1X9Z0PyYf777XgGbtQ4=;
        b=0H06H2EuE8PINjwKut4jq5Ncgb7gnari/+oOtR6wb8c26uK2BBtEM4Kjawwc9ZxUpn
         ErhkN1Dr3hp7GfLu3P8+Dm1ZhEojDIBHfYBSj009vU238hFIS8Nu4k86QxzOf7YVQKoO
         C7nImaXb8DGDW07XSjPevZbIQkkFb9KM5C8GxiJwJqhxjBdEBr99SbsfIHx5utrzeuQl
         WnVlonFsRvlAAIhvzExyADMsOJrwo8x7b44wp1dNEaOw1s1KWlpWnhXhPmhahgCyLIIO
         d+y8qq6YvksJm0MFesxv2TDj9/RXxxiFmp3SD/xnaTGyz25yGOIVlS9w00Tr8y/aM8B3
         gp+Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) smtp.mailfrom=arnd@arndb.de
Received: from mout.kundenserver.de (mout.kundenserver.de. [212.227.126.135])
        by gmr-mx.google.com with ESMTPS id r11si417059wrl.3.2019.11.14.05.51.37
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Thu, 14 Nov 2019 05:51:37 -0800 (PST)
Received-SPF: neutral (google.com: 212.227.126.135 is neither permitted nor denied by best guess record for domain of arnd@arndb.de) client-ip=212.227.126.135;
Received: from mail-qk1-f173.google.com ([209.85.222.173]) by
 mrelayeu.kundenserver.de (mreue012 [212.227.15.129]) with ESMTPSA (Nemesis)
 id 1MREqy-1iGruv24t2-00N6Bk; Thu, 14 Nov 2019 14:51:37 +0100
Received: by mail-qk1-f173.google.com with SMTP id d13so5010194qko.3;
        Thu, 14 Nov 2019 05:51:37 -0800 (PST)
X-Received: by 2002:a37:58d:: with SMTP id 135mr7491492qkf.394.1573739496258;
 Thu, 14 Nov 2019 05:51:36 -0800 (PST)
MIME-Version: 1.0
References: <0000000000007ce85705974c50e5@google.com> <alpine.DEB.2.21.1911141210410.2507@nanos.tec.linutronix.de>
 <CACT4Y+aBLAWOQn4Mosd2Ymvmpbg9E2Lk7PhuziiL8fzM7LT-6g@mail.gmail.com>
 <CACT4Y+ap9wFaOq-3WhO3-QnW7dCFWArvozQHKxBcmzR3wppvFQ@mail.gmail.com>
 <CAK8P3a1ybsTEgBd_oOeReTppO=mDBu+6rGufA8Lf+UGK+SgA-A@mail.gmail.com>
 <CACT4Y+YnaFf+PmhDT5JRpCZ9pqjca6VeyN4PMTPbCt7F9-eFZw@mail.gmail.com>
 <CAK8P3a1viWDOHPxzvciDt8fPCm3XkbLJxAy1OjtJ_-vuP-86bw@mail.gmail.com> <CACT4Y+YsC7yX5d8Gw=C7pm_4xcZ1wjzb_=AoPOL1k5FEPERbzw@mail.gmail.com>
In-Reply-To: <CACT4Y+YsC7yX5d8Gw=C7pm_4xcZ1wjzb_=AoPOL1k5FEPERbzw@mail.gmail.com>
From: Arnd Bergmann <arnd@arndb.de>
Date: Thu, 14 Nov 2019 14:51:20 +0100
X-Gmail-Original-Message-ID: <CAK8P3a2BX==aF7LezgxxtPbRX=GY09Bug+jPH+qL5kam13mjmg@mail.gmail.com>
Message-ID: <CAK8P3a2BX==aF7LezgxxtPbRX=GY09Bug+jPH+qL5kam13mjmg@mail.gmail.com>
Subject: Re: linux-next boot error: general protection fault in __x64_sys_settimeofday
To: Dmitry Vyukov <dvyukov@google.com>
Cc: Thomas Gleixner <tglx@linutronix.de>, 
	syzbot <syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com>, 
	John Stultz <john.stultz@linaro.org>, LKML <linux-kernel@vger.kernel.org>, 
	Stephen Boyd <sboyd@kernel.org>, syzkaller-bugs <syzkaller-bugs@googlegroups.com>, 
	"the arch/x86 maintainers" <x86@kernel.org>, kasan-dev <kasan-dev@googlegroups.com>, 
	Jann Horn <jannh@google.com>
Content-Type: text/plain; charset="UTF-8"
X-Provags-ID: V03:K1:BXq/oKUA1pCECNqq6sh89YW4H3FZ7ZWlAZeOyxW+8XFptaPUUlP
 uX9Vl0+dvO9D7DiX8RzJZh4Ji6KzZZzKas5IoLJxUJ6VdL4FCNPfELt55zNlwMA15VBwJSO
 +RsX2GlJTWgAK/JqR655TYaZH3+DJO86ngrGA8Hrw+YA3X5hBWGIjAOCl0hwMyvBJJ/Xh6z
 Lfzz4EO7lIu4kC4OoAxiQ==
X-Spam-Flag: NO
X-UI-Out-Filterresults: notjunk:1;V03:K0:OAFV2TBCvQI=:d+LVTagGesOTEquoCpv7o5
 rEM27tuOp/0T8rzcp+IevZzXrQxwnaSMozHPMCN2ybMi9xWE75ZNwNObN4FEoC23o/AwFwaTD
 GAvdjk4mhCpeJdvcyle3/H7uhi2+XqwZANWUWbKmzLuQUADbLO9Rvn49bGJcULbNXzhY7V8TD
 Aq4rglIcNVhJ6CR9CJFyY/Q8kadKIscb0wE/T9JuR8GDz5YbWbA64WbmEUfhj2hjxqZaXK+xt
 DiBIggJSp//XqVVX9gcfwo3x319aliDehMueqfe6xo6JrzqkYUhhCIlT5Qm42nWBag3rMOfpK
 odj7kycMUTt0KSB3CAV4okuPvUtqUPd4IZke49lvTh2TEvC58T7KWaVHDg9nWVZgf6SjZCj1o
 9N+FKfFhG9TX3IHcUmIjrBtw5fKQXH0uao6PCIl4zH/SsjFi7jjiuVDAkBu2oFhBegeBwoeqa
 UGwbMZm17yDc65X6HBLFDwWIjwlRcfvZOWlySxQ9W5ifhDsPeauSupeaC3u6Q0uuaKYNLgaGb
 SdSElcZcV4tnbZS2tLQjDhVS6OJdyW1wlP/zyPnfFNnv/aGKwb/bs8iBBlTpx8h84S37DKzzp
 2Tr/f67nkIhxzK0/bhYko0rJTHjDq5W3oEx43hNEIwKt48swSEo/Rj0CFl/PHw1iFOI8yIuOG
 D2N457HnGnTnwcNshmO6ZVSokLvdBZS3TPtx/w1zOH06O39UnKPyHxi0AIfJ2WhWdUuiqZvBi
 lnmNt240oB6AW3GiRL2/KFEl51CzswLEpZHOSs9d4p9KMiUOlkn5moGodAyewfCiOs2EkxZ4c
 ZkJCQTadf6DMpUVB+7fw4sFuISXpgrLNgIgwYFD0OFSCN0YGI6MC+dXRUJbulmOsdsPByzu0T
 Tt8AA458CTQY+qbYHpuw==
X-Original-Sender: arnd@arndb.de
X-Original-Authentication-Results: gmr-mx.google.com;       spf=neutral
 (google.com: 212.227.126.135 is neither permitted nor denied by best guess
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

On Thu, Nov 14, 2019 at 2:39 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> On Thu, Nov 14, 2019 at 2:38 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > On Thu, Nov 14, 2019 at 2:28 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > On Thu, Nov 14, 2019 at 2:22 PM Arnd Bergmann <arnd@arndb.de> wrote:
> > > > On Thu, Nov 14, 2019 at 1:43 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > On Thu, Nov 14, 2019 at 1:42 PM Dmitry Vyukov <dvyukov@google.com> wrote:
> > > > > > On Thu, Nov 14, 2019 at 1:35 PM Thomas Gleixner <tglx@linutronix.de> wrote:
> > > > > > >
> > > > > > > On Thu, 14 Nov 2019, syzbot wrote:
> > > > > > >
> > > > > > > From the full console output:
> > > >
> > > > > >
> > > > > > Urgently need +Jann's patch to better explain these things!
> > > > >
> > > > > +Arnd, this does not look right:
> > > > >
> > > > > commit adde74306a4b05c04dc51f31a08240faf6e97aa9
> > > > > Author: Arnd Bergmann <arnd@arndb.de>
> > > > > Date:   Wed Aug 15 20:04:11 2018 +0200
> > > > >
> > > > >     y2038: time: avoid timespec usage in settimeofday()
> > > > > ...
> > > > >
> > > > > -               if (!timeval_valid(&user_tv))
> > > > > +               if (tv->tv_usec > USEC_PER_SEC)
> > > > >                         return -EINVAL;
> > > >
> > > > Thanks for the report!
> > > >
> > > > I was checking the wrong variable, fixed now,
> > > > should push it out to my y2038 branch in a bit.
> > > >
> > > >       Arnd
> > >
> > >
> > > This part from the original reporter was lost along the way:
> > >
> > > IMPORTANT: if you fix the bug, please add the following tag to the commit:
> > > Reported-by: syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com
> > >
> > > https://github.com/google/syzkaller/blob/master/docs/syzbot.md#rebuilt-treesamended-patches
>
> /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\
> this

Ok, got it. Now pushed out with a

Tested-by: syzbot+dccce9b26ba09ca49966@syzkaller.appspotmail.com

     Arnd

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAK8P3a2BX%3D%3DaF7LezgxxtPbRX%3DGY09Bug%2BjPH%2BqL5kam13mjmg%40mail.gmail.com.
