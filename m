Return-Path: <kasan-dev+bncBC7OBJGL2MHBBGMBSHWQKGQEK4QFR3I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3c.google.com (mail-yb1-xb3c.google.com [IPv6:2607:f8b0:4864:20::b3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 8A043D5EEE
	for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 11:32:10 +0200 (CEST)
Received: by mail-yb1-xb3c.google.com with SMTP id p66sf13458955yba.0
        for <lists+kasan-dev@lfdr.de>; Mon, 14 Oct 2019 02:32:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1571045529; cv=pass;
        d=google.com; s=arc-20160816;
        b=LyLxphBiRr16Umbh8dD0OLkdjPb4SZvGs/xa9D8UShDSg2TQoLKCsNrGjrKqcL50oS
         PfTmht87WBCi9rYL77J4zLvTT2EfB+5w3TBHAOSHBakDsjg2crRIj/mFmmzClocc+om+
         ST3vrkhhuhFz+6N7/r8d9JBDzt9+/oUkPg4s7fj6aAMEU5Waxh/xndccWtJkeMB/oAMl
         tPj6TejaJ93kstSC1QrRzX0Xe0QW6+TphKTn50KW4zcjzix1yeXZ4DoT41ctMvaksDvZ
         2LJvah22tqyhxgnNkDhFfo2BzSVD50Fd3rkkpSom4kEmJR1o5sb7AwCzDiTvmfybKCUs
         4nVg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:content-transfer-encoding
         :cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=OMU3qTnsEI6/ONj7cqyIwzOgQx/hGWzA0kPPonkjqZI=;
        b=FAKvKQcH6umoJZ5RvHZwMXzlb3oD0CCtIUuLbeo7+dhzaSbfsSQDpLWB+F4ZV1W2yF
         9cgNx0UEkhpscFJcpVRjfSrjOOzlxN29gMLcgirxwh6oszvjcudR7ryMe4RuuSUwlccm
         JEDtc6dR9UlNcwNkcnx7sGghfnBdhaJ5NhpdgWvWct5/mf54i4wq2Z22V0BPZyVmL9VR
         tHCSh9Fl3+mgO/DCMfn4Tpj2ST1SGXy3Zq+niV9rpCvPuE7QAaHKKUxNZjYty0s4yaD0
         k5Z8eF3Yce1MuiHTvABl34TZbR0/ihj6X9UUPTpeOpaSYNdRl4A+Qn+aBLC50oTem83A
         6NBw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NO3t0VB0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:content-transfer-encoding:x-original-sender
         :x-original-authentication-results:reply-to:precedence:mailing-list
         :list-id:list-post:list-help:list-archive:list-subscribe
         :list-unsubscribe;
        bh=OMU3qTnsEI6/ONj7cqyIwzOgQx/hGWzA0kPPonkjqZI=;
        b=ZHKJVbPNpX50Y1f/aXdVV9dBkTEbau01EAevbXE20Wr1Xh6JGbGNGhNFqp7hUuV/0X
         SPwU1mP0iteqvYUUBwKtSZWzq2sGOvPU4o+i/VpnHW6vYtYkHiPSHjYxLJ7JkK6glUz2
         YEwLkeeuYbynyl2BwEdU6o/57Oq/2xYkXTx8ob9hRNPDtrw1Hwb+UrUYeGIYZVYTwftE
         RmXWmDqB9PC75abyrQtIk/+sNmA0yuuQfv3UKuL3gx9E8AI+Ex+EWwOswfXq+1oYbL8O
         WL4LhC772EbUC6+4yWil7sQflgWSPX2QSp1zK7srZx5gMk2KkrB/99qM8+UcZFte83cF
         XJtA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=x-gm-message-state:mime-version:references:in-reply-to:from:date
         :message-id:subject:to:cc:content-transfer-encoding
         :x-original-sender:x-original-authentication-results:reply-to
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=OMU3qTnsEI6/ONj7cqyIwzOgQx/hGWzA0kPPonkjqZI=;
        b=pSpN3JYZE9kqBRgRCNHnE04OMW22oWN+3WDcx9qn+YHRTn3uqQtt5gxOP0gzKnshB7
         ulM1oj2Wj8TUcaDpXvEZh+iUSSuCSslyTRireJ0BXP5s69iJxJJGmlU3YwrhhCIEt4Jw
         0D6h919JxUG0U4FTd5xYIivGe9OE18XFC+L3OxdLw+O+XdXgWCaoNBsVXqCGkn5EUemt
         pIKb1wrdHwAPXawYGoZzattuY+CUMHO04cxmxhFCZqHyaWd34bEfhtgGFiIPXLASS9lZ
         wODXd/755s5OHRBu4XhIMNEbdpqMUu4fMPX2N/5HvyP9k9L+fWSio6zWGd2hvpKS8Pz8
         28tA==
X-Gm-Message-State: APjAAAUIKkhhNvUfke0nNPtICK5Zb0+HZu4nVLY0x0DwwQgpjHKTNdQI
	fj7+o0TPite2uGKXu2EQ3TU=
X-Google-Smtp-Source: APXvYqwr/LLqixB4yfaYWuOVonkoCPSRg7+58LZfRi1B0os5u7tp6547qF3ZYV1suUO0IoGdyBqTRg==
X-Received: by 2002:a25:d048:: with SMTP id h69mr18172035ybg.453.1571045529483;
        Mon, 14 Oct 2019 02:32:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0d:d611:: with SMTP id y17ls1880079ywd.13.gmail; Mon, 14
 Oct 2019 02:32:09 -0700 (PDT)
X-Received: by 2002:a0d:d7d5:: with SMTP id z204mr12536130ywd.265.1571045529085;
        Mon, 14 Oct 2019 02:32:09 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1571045529; cv=none;
        d=google.com; s=arc-20160816;
        b=CkGE5zbgkHkLQrfra17KfWN3Zh7zlfy0O90SIA1ixW7kxNvjoCT6FijxuUeLNEtYMu
         Qiw4HfnOPQaKitBzWOtA7yqkHCBu80Yil8YOBlx4Dha0o36ra46O0Ovit/6qrTOVc9Sn
         fxCGvKiQAuqQVsA9g2DeWCg9bA0shEXvGHh8qpoxwPRSiadzNKT0HS33BjAMycYjcVsr
         monaDgW688QU6uJeeLMVjc70yHGLHfGvomj/RsnkjThg0RosuROK7QpDx2MddPkPE2hl
         JtklSCXEceeeN7eqOFcaWkgTX5MtfzX3I20kA3pBqptCZF9FI4lfnzL8/dqVADmVlbsH
         hShw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:dkim-signature;
        bh=6jj0LWwH0UFM3yMv+6fFI2lCptwbKbPuAlHLCa4o8Ig=;
        b=LbXhoNR0pnkQJi37yBDi5uInk4/Ps224/GX+IhCp3l/3qKJ/SGlOj2MpWv2UnY/jA6
         WPHbSXao+CF71hq3Ghb1wze7WCyF1kTPb06Wl7gcJgncS0l5edbs6fkAuM+ZvvIXP1Eo
         oCBrFk7GcXNUFLjpGGlr6guJUDMDxcLRNK3QaVwou/S7c5s2tNchxE5Bhv7z8ZMUUuHF
         jLmsTShUNNX9E3rntJW2MSpjpUWJ0cqIS5jwEQYSS15GRx4TojkUZSVSl7VjHncPQOcX
         S74zwN6BWHvi/aZ5jTkGs4SR/+EQd1LCMzflaJ9u1mydNXtPor+iFqqBFq/wAvu2kA8N
         O8cg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@google.com header.s=20161025 header.b=NO3t0VB0;
       spf=pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) smtp.mailfrom=elver@google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=google.com
Received: from mail-oi1-x244.google.com (mail-oi1-x244.google.com. [2607:f8b0:4864:20::244])
        by gmr-mx.google.com with ESMTPS id p140si1717514ywg.4.2019.10.14.02.32.09
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Mon, 14 Oct 2019 02:32:09 -0700 (PDT)
Received-SPF: pass (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as permitted sender) client-ip=2607:f8b0:4864:20::244;
Received: by mail-oi1-x244.google.com with SMTP id k9so13194325oib.7
        for <kasan-dev@googlegroups.com>; Mon, 14 Oct 2019 02:32:09 -0700 (PDT)
X-Received: by 2002:aca:f492:: with SMTP id s140mr499222oih.83.1571045528182;
 Mon, 14 Oct 2019 02:32:08 -0700 (PDT)
MIME-Version: 1.0
References: <000001d5824d$c8b2a060$5a17e120$@codeaurora.org>
 <CACT4Y+aAicvQ1FYyOVbhJy62F4U6R_PXr+myNghFh8PZixfYLQ@mail.gmail.com>
 <CANpmjNOx7fuLLBasdEgnOCJepeufY4zo_FijsoSg0hfVgN7Ong@mail.gmail.com> <002801d58271$f5d01db0$e1705910$@codeaurora.org>
In-Reply-To: <002801d58271$f5d01db0$e1705910$@codeaurora.org>
From: "'Marco Elver' via kasan-dev" <kasan-dev@googlegroups.com>
Date: Mon, 14 Oct 2019 11:31:56 +0200
Message-ID: <CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw@mail.gmail.com>
Subject: Re: KCSAN Support on ARM64 Kernel
To: sgrover@codeaurora.org
Cc: Dmitry Vyukov <dvyukov@google.com>, kasan-dev <kasan-dev@googlegroups.com>, 
	LKML <linux-kernel@vger.kernel.org>, "Paul E. McKenney" <paulmck@linux.ibm.com>, 
	Will Deacon <willdeacon@google.com>, Andrea Parri <parri.andrea@gmail.com>, 
	Alan Stern <stern@rowland.harvard.edu>, Mark Rutland <mark.rutland@arm.com>
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: quoted-printable
X-Original-Sender: elver@google.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@google.com header.s=20161025 header.b=NO3t0VB0;       spf=pass
 (google.com: domain of elver@google.com designates 2607:f8b0:4864:20::244 as
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

Hi Sachin,

My plan was to send patches upstream within the month.

Thanks,
-- Marco

On Mon, 14 Oct 2019 at 11:30, <sgrover@codeaurora.org> wrote:
>
> Hi Marco,
>
> When can we expect upstream of KCSAN on kernel mainline. Any timeline?
>
> Regards,
> Sachin Grover
>
> -----Original Message-----
> From: Marco Elver <elver@google.com>
> Sent: Monday, 14 October, 2019 2:40 PM
> To: Dmitry Vyukov <dvyukov@google.com>
> Cc: sgrover@codeaurora.org; kasan-dev <kasan-dev@googlegroups.com>; LKML =
<linux-kernel@vger.kernel.org>; Paul E. McKenney <paulmck@linux.ibm.com>; W=
ill Deacon <willdeacon@google.com>; Andrea Parri <parri.andrea@gmail.com>; =
Alan Stern <stern@rowland.harvard.edu>; Mark Rutland <mark.rutland@arm.com>
> Subject: Re: KCSAN Support on ARM64 Kernel
>
> On Mon, 14 Oct 2019 at 10:40, Dmitry Vyukov <dvyukov@google.com> wrote:
> >
> > On Mon, Oct 14, 2019 at 7:11 AM <sgrover@codeaurora.org> wrote:
> > >
> > > Hi Dmitry,
> > >
> > > I am from Qualcomm Linux Security Team, just going through KCSAN and =
found that there was a thread for arm64 support (https://lkml.org/lkml/2019=
/9/20/804).
> > >
> > > Can you please tell me if KCSAN is supported on ARM64 now? Can I just=
 rebase the KCSAN branch on top of our let=E2=80=99s say android mainline k=
ernel, enable the config and run syzkaller on that for finding race conditi=
ons?
> > >
> > > It would be very helpful if you reply, we want to setup this for find=
ing issues on our proprietary modules that are not part of kernel mainline.
> > >
> > > Regards,
> > >
> > > Sachin Grover
> >
> > +more people re KCSAN on ARM64
>
> KCSAN does not yet have ARM64 support. Once it's upstream, I would expect=
 that Mark's patches (from repo linked in LKML thread) will just cleanly ap=
ply to enable ARM64 support.
>
> Thanks,
> -- Marco
>

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/CANpmjNPVK00wsrpcVPFjudpqE-4-AVnZY0Pk-WMXTtqZTMXoOw%40mail.gmail.=
com.
