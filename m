Return-Path: <kasan-dev+bncBAABBWM3T7ZAKGQE4A6IAGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-ot1-x33f.google.com (mail-ot1-x33f.google.com [IPv6:2607:f8b0:4864:20::33f])
	by mail.lfdr.de (Postfix) with ESMTPS id 149B315FE0E
	for <lists+kasan-dev@lfdr.de>; Sat, 15 Feb 2020 11:54:19 +0100 (CET)
Received: by mail-ot1-x33f.google.com with SMTP id t17sf3785201otk.22
        for <lists+kasan-dev@lfdr.de>; Sat, 15 Feb 2020 02:54:19 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1581764057; cv=pass;
        d=google.com; s=arc-20160816;
        b=ghbOVKw1BDg+2PzWmbHB5XJRnwroOLO/6S54zALBelg6qyxr26S0MPmVqHBhsV05qy
         HmyH21zgLkGrSSUoefw+2CvaJLa2++ZgD3LfY1Kafj2tmuCMDjgC72z7gCSKH6AOaKYb
         n0hgdD+BvSHpx33kh2nIariJLfsLp5mrkNkYMecMPKURsnX+/rj+STBvncAy9A+h+m62
         Kyiwtq9GqcKqIa/jIwh5rQVN9t/2bdQnip8i8sBRZmiLXCFpn+1yQDTKq1b9rgjp98pR
         DO4S4it/jtcZPjhymXtGQYCfPFiZh+fA1QQmqtCFSZBdvY36idZ9LKXoLttNNmQf6KDm
         xi7A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:user-agent:in-reply-to
         :content-transfer-encoding:content-disposition:mime-version
         :references:reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=kn1KRho39I5eS2LYT/j/Y9XDNdEFvJtosrb6QPcy2Ck=;
        b=kCk1ybTcRRl+oAMtU+ZX5xVhYKHGKtS74yTDUbfl0CPqdHdGvYaI6iMY/sVuFmZjIT
         HzhtNYPmWwxIwcarxGFYoT2eUNYRFDMqUnA6WkFNcAVYw444OvuRuF21N3FP3VRSfxmu
         aQRmW0mnA7adDD8zO5iBXFDDw/eAb2lv5uvAw6uNkN5AGbgMNZf6Hx66PvbCSrB1A9cg
         +Leh7XDTD/IY/thOsiJwdebzZXG/UOWWKri2T1Y6necf82wnY2+wnFDbc5vEPzzS/7Qz
         xTr/GIOrPiQK3HWJhhKbf2aZfrbRZKnApUEKniO8ADnEG8Lnm5ROe33gOz+lZxnHgAc2
         0NHQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qVB8UnaO;
       spf=pass (google.com: domain of srs0=czr5=4d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CzR5=4D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:reply-to:references
         :mime-version:content-disposition:content-transfer-encoding
         :in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=kn1KRho39I5eS2LYT/j/Y9XDNdEFvJtosrb6QPcy2Ck=;
        b=tK8lUHf+rp+fLFU0NqcybNnUTDYiGfnPBoTNQ9WJAihIYy7VZOukn1zrkRDw6xOh/m
         RHYe1ZQ4vqHYHXyb4xA+UGVl8VU0S3IsBS9BcoaV4oA8ObUBKWeEhC17Aso5yFTPyxAv
         hfiSQB+iDywfi/FVieBsVAgCKRCqqBJ9PNCPiDLuh36S4oSHlPYBEqgmaHwpLcTdabKW
         r655+kOvDWkFtEqlvQW/IBJrafQemT9MkGVJmaRBZPv8AIKvXfMpEe8RoHCxdSl02HwM
         xaqmYN/PTBfJMnw6HjkL95KT2fmRdTwYx3itqaB0+GTymTeI2NwJMh5KTlL+Pr5tHYsO
         t9Cg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :reply-to:references:mime-version:content-disposition
         :content-transfer-encoding:in-reply-to:user-agent:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=kn1KRho39I5eS2LYT/j/Y9XDNdEFvJtosrb6QPcy2Ck=;
        b=eV4mCeO67EyrL4E3F40Sd54KYjXuxHvQY+OP77CUvdQrAjVLLcP3Lz1jHeb3UVehv2
         2669BR9cEJeebuNg2TbdI84YBnolsE0sfhTbBO1hzqubXGZwD7FlUO0GHmDm+j3n1bfJ
         mjdD797Ao78CYUYr8AfC4epS73LKX0iJSe9vLg/LwXGi65Y4GRC7Y79vqIkHLM6KAeQh
         heqVHBW5O+nUng3iiPOdkL7w7KHzYR4zY7qtXyNCIjlP8lh4htcT3M5nCPJr6FiFgOTX
         ZuYCHBxrQ3YC+r8BxBLIhjj/gr5mQiYFoA8hxsr+cy3Q3RNfpOQ/+RZ5xcDHQKXwPkEr
         p8tg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAVxfElMkHIjct83STkVXnzNizCbyOc+5gtiNTmtJLvKTOhE5NXN
	jCQzdx9hdSk/Ut6XgkilXLc=
X-Google-Smtp-Source: APXvYqx+ITB2uFmY/PAKsBTYD1w+upjdzKBP61RAwo8htsMntrVKdlsb6FTYSo5ftMTaMta7Cukzmg==
X-Received: by 2002:aca:f584:: with SMTP id t126mr4818141oih.132.1581764057513;
        Sat, 15 Feb 2020 02:54:17 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6808:a0a:: with SMTP id n10ls420871oij.0.gmail; Sat, 15
 Feb 2020 02:54:17 -0800 (PST)
X-Received: by 2002:a05:6808:244:: with SMTP id m4mr4689352oie.125.1581764057150;
        Sat, 15 Feb 2020 02:54:17 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1581764057; cv=none;
        d=google.com; s=arc-20160816;
        b=WT+m7C9kTyhH6EggIYDXZWv9sS4H7LnAHDph2Vv8+gNkCNMDygwj8YrzhjdO43ISUH
         DKBuGpA4mnUzXtQCQpdfoJpEXg+epj6gqMlxU45heKtMMJbBJ5GUOgNQ6cRz8mlynglR
         /u6citP5N1XEoI1zvL0ng/wtt+FRg8d4/tUO9PX+zyR0A+QbKdasQKKJ3u6PWG1VrZrT
         awUTqwEmTg4vOP9JZNAv/SS7Oeay/Ydvy4CtNzFJ8OFLFVulcQPcmVkrajDW4TPQH89X
         FEbpvvk7Nww+i5iI7VFaHeiNM0zqE0hwMpDZ8vgiRZwe/SOFxtimDGYMZ6qpfc8R2X3j
         x8QA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=user-agent:in-reply-to:content-transfer-encoding
         :content-disposition:mime-version:references:reply-to:message-id
         :subject:cc:to:from:date:dkim-signature;
        bh=QEb7EaJuNweQExL/KPpmp9YtYWhVAcly6nVuqH0AqcI=;
        b=yTuHqtGB0z90UVg2uWs5DlYVMrtGvgwMw1vSC+IxchAqxKe+KU8QzRv1jngZRneMbl
         bhMr84NE5kZiT1axFZkd3/P4KCkpd1ntVV6dvSQswh9Sf3ySxbRHetpAETUhZVC5g6ug
         7paD1Rh1Nky7Irgxezg7x4Le8Xtt9HU4UrkIvPEAzk0ZvZDBEEqecxc5EvtXJSoyEKfz
         UpC8HL4Dw11vvgk8BL8jOK+Mn+p1PnOVd+zFnPxVjnK3riS75UfPIVGh7aNiuGKESqgs
         89hLP9jL7zZLy3xk2E/kuNnh4f/rOG8rm3zmN3XM8Wx7WxJ6KHaTLiD+HWQwJKc6VtT/
         ZlJA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=default header.b=qVB8UnaO;
       spf=pass (google.com: domain of srs0=czr5=4d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CzR5=4D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id 14si270204oty.3.2020.02.15.02.54.17
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Sat, 15 Feb 2020 02:54:17 -0800 (PST)
Received-SPF: pass (google.com: domain of srs0=czr5=4d=paulmck-thinkpad-p72.home=paulmck@kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: from paulmck-ThinkPad-P72.home (unknown [62.84.152.189])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by mail.kernel.org (Postfix) with ESMTPSA id A3BF020726;
	Sat, 15 Feb 2020 10:54:15 +0000 (UTC)
Received: by paulmck-ThinkPad-P72.home (Postfix, from userid 1000)
	id 9DE103520CAA; Sat, 15 Feb 2020 02:54:13 -0800 (PST)
Date: Sat, 15 Feb 2020 02:54:13 -0800
From: "Paul E. McKenney" <paulmck@kernel.org>
To: Qian Cai <cai@lca.pw>
Cc: Marco Elver <elver@google.com>, kasan-dev <kasan-dev@googlegroups.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Andrey Konovalov <andreyknvl@google.com>,
	Alexander Potapenko <glider@google.com>
Subject: Re: KCSAN pull request content
Message-ID: <20200215105413.GX2935@paulmck-ThinkPad-P72>
Reply-To: paulmck@kernel.org
References: <CANpmjNMi3jQaqEB54ypWh2xEKCVRzBesMMfV0zZBcANWbXrcAw@mail.gmail.com>
 <E25FEB93-DAE8-4ADA-B477-920B230CEFF4@lca.pw>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Disposition: inline
Content-Transfer-Encoding: quoted-printable
In-Reply-To: <E25FEB93-DAE8-4ADA-B477-920B230CEFF4@lca.pw>
User-Agent: Mutt/1.9.4 (2018-02-28)
X-Original-Sender: paulmck@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=default header.b=qVB8UnaO;       spf=pass
 (google.com: domain of srs0=czr5=4d=paulmck-thinkpad-p72.home=paulmck@kernel.org
 designates 198.145.29.99 as permitted sender) smtp.mailfrom="SRS0=CzR5=4D=paulmck-ThinkPad-P72.home=paulmck@kernel.org";
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

On Fri, Feb 14, 2020 at 11:33:14PM -0500, Qian Cai wrote:
>=20
>=20
> > On Feb 14, 2020, at 5:40 PM, Marco Elver <elver@google.com> wrote:
> >=20
> > False positive appears to be quite subjective when it comes to data
> > races, and everybody has a different set of preferences. We know this,
> > and KCSAN is already pretty configurable
> >=20
> > What is your definition of false positive?
>=20
> I feel like all the annotations are false positives because of the existi=
ng code is correct, but only the KCSAN complains. I knew we had this conver=
sation before and I agreed they are still data races from a compiler=E2=80=
=99s POV, but kernel developers are not all that into compilers.
>=20
> BTW, I have seen a lot of annotations kernel patches for sparse recently.=
 My gut feeling is I don=E2=80=99t want be that guy, and I don=E2=80=99t wa=
nt to use sparse at all because I have only seen most of them are annotatio=
ns and rarely any real *fixes*. Maybe I am alone in that thinking=20

There is a wide range of opinions across the developers and maintainers.
For example, I am just fine with the current 20-to-1 KCSAN "false positive"
rate because the bugs it found would have taken far longer to locate and
solve than the little bit of marking required for the other 19.

So my suggestion is to learn what each maintainer is looking for and
work with us to produce the needed filters.  For example, although
the scripts in the following (not yet public) document don't do quite
what you need, perhaps they can serve as either starting points or
sources of inspiration:

https://docs.google.com/document/d/1wZVt-0ecCpl5kaz9kc4lxFjWVjb5mzeQYED0VFe=
Lz9Q/edit?usp=3Dsharing

Other things Marco and his group will be able to filter within KCSAN,
as they have in fact been doing, much to their credit.  But we will need
to work on both ends in the near future.

My belief is that longer term, the community will go through the same
transition with respect to KCSAN "false positives" that they did with
compiler warnings.  20 years ago, a default kernel build was quite
noisy, but people slowly realized that the noise was hiding important
diagnostics.  But it will take time for this same process to play out
for KCSAN.  In the meantime, we are going to need to filter its output
carefully in order to keep the noisier KCSAN detractors in the commmunity
from causing the rest of the community to reject KCSAN.

If enough of the community appreciates the filtered diagnostics (much
though we might want them to also appreciate the unfiltered ones!), then
over time they will want to slowly remove the filtering.  Just as happened
with compiler diagnostics.  But we have to avoid initial rejection,
and that requires us to strive to be helpful, rather than (as you say)
"being that guy".  ;-)

Yes, it is slow.  But we do need to maintain the right balance between
patience and impatience, and that balance will unfortunately vary from
RCU's "all KCSAN diagnostics right now!" to other subsystems' "keep this
KCSAN thing out of my face!".  And the trick is to prevent the "keep
KCSAN out of my face" people from keeping KCSAN away from those who
already understand that they need it.

Seem reasonable?

							Thaanx, Paul

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/20200215105413.GX2935%40paulmck-ThinkPad-P72.
