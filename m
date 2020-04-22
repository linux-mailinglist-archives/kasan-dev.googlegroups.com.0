Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBXFFQL2QKGQET3GWUWY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qk1-x73e.google.com (mail-qk1-x73e.google.com [IPv6:2607:f8b0:4864:20::73e])
	by mail.lfdr.de (Postfix) with ESMTPS id 9C0A31B4CE8
	for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 20:54:22 +0200 (CEST)
Received: by mail-qk1-x73e.google.com with SMTP id c140sf3916529qkg.23
        for <lists+kasan-dev@lfdr.de>; Wed, 22 Apr 2020 11:54:22 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1587581661; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIlPgwo4mAOw7gbDywACr6Rjd0DHWF5jrBD12kwPCz/TPDGJySkzb6QVvf1VcASvgl
         he781lFRVBlpInszeqf19TftgsiFKY80Eivl67jEtonSFMwGYURoPHGNLK8C2Ej9vAIO
         ww5klbF5ii1eAanU5oQyXWq9VYH0HE5C0ziFgcaSMTfA1OcFL7tV8eifrWcTe1jcFlgR
         quswYmgFW38yCMT1Sus3kKCkRXNWb9oz813G0dg5Lac1eUxufUEn6Bt4MeUWRjw3prEE
         yeYeItBWipV7nbDk3raClUFG/gEFpJj5MJUwwPJsAuUxv7Tbi0hT3yN1PZ9T5eaMu+RS
         1xHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:references:message-id
         :content-transfer-encoding:cc:date:in-reply-to:from:subject
         :mime-version:sender:dkim-signature;
        bh=VjOIcGlV9UC8XuqGS8rJ1b36VmrhnHeYPV/+S0T2wBU=;
        b=Ws364zJMTH33+doSktkXaK7eM9mr8UnoS20d806I8WG/v/J/pcv74fQQ1X1Iy4r9JV
         WkxdSYKVfHk5LvlZuq8Q3cJX8Sqgvt8fBXIbBcGgaWmIH6qFwlYhoDiPOPbrvnUOR/MD
         D8vYin7wLXXe73FHJbyJw91hcGSKxWqYRgU+eltlU5DR27eqgsOxghJ+ulJsc+16seA8
         Y2c+6oi+AML/isAclCC5GN5sTzI50BibMvdXX+JxEkYLAYUhFkuRqJabGBBArhG1YaBg
         jBJjtEpzXB7xUVh+2Kjc0zperNx7M8jrAG+aQEmiIeR0WgahfGlQIW766cMNcnldxthy
         SKbg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=KcTXmBwo;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:subject:from:in-reply-to:date:cc
         :content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=VjOIcGlV9UC8XuqGS8rJ1b36VmrhnHeYPV/+S0T2wBU=;
        b=q5gCV8ltiPuxu8ORqWfMXxfz6d0bVIR2+MWkOXTLFdLLak97tjNoi4NOcjWwwln0Ps
         KXm54GKkO/aCwRrqR2SdVcuClDG8XvyDACLGnN7F5859lox9itG6MHn+dBdvvEb3M9q4
         bu2Z1BmD244ORVxP1Wm6XvxZv4st168/dUNbfaEcmVkX7OOVsWe2pcaMXYomboxyzkRc
         ONZKgjjUTvi5VoJrsu2lk4QmLXiBMLZYXGgY8IAlFy+NDdEc8MATrenNwc0n25Qm7dNA
         K/J++ksvSaZSklvoYJ7zOOsCqfgyME6O0a4oLBZru2AcWdQYFZVBkWPHVnsxNG7/wgXw
         Fzjg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:subject:from:in-reply-to
         :date:cc:content-transfer-encoding:message-id:references:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=VjOIcGlV9UC8XuqGS8rJ1b36VmrhnHeYPV/+S0T2wBU=;
        b=JdmAp5QtBpT75JSD7APHxc1wtsKxG5gg4b2JyIw0e4TXnoKgCJhbEKdKlqNtkZyU4Q
         JYx2DFryGtstBKp4q1BtKscMeBXc6B3uGHzAyfOtfZGOxcB4SkbwV5na2dHe9kGu4EJ3
         MLvu6YyEzaUFCRJ09DMEOXd2KFxVc2A8q35f6EQLw1037ekSOcC8Iz0P93GbmoQrBJDY
         ql01Dr7lL1nO5SEx0T85DauzusJQ6jQazO1ooEIx5Yng6+YLPVe3qAFmmT2RSCh3abAr
         WwnhDUXGQRpjwhNFbMqZK9TJNnwGFIe426UmPdIaVk6rB/bO/egcrD+DBAT30H6ZrkgK
         tE6Q==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AGi0PuZEUgKhOoAXIpQ21aN9AQavP0d8hMAgkauldYJu0sraoSB7U1Cl
	9jjsh9xoB659kcclWyck7Wk=
X-Google-Smtp-Source: APiQypL5a0rVM9N9zp5dr1kPZ4u7ELdc0K65UCp29i3qj/waN+BfXPUM0okg4wvw8NWkdKRZYJZrzg==
X-Received: by 2002:a37:9445:: with SMTP id w66mr25810472qkd.15.1587581660907;
        Wed, 22 Apr 2020 11:54:20 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a37:c97:: with SMTP id 145ls2034981qkm.4.gmail; Wed, 22 Apr
 2020 11:54:20 -0700 (PDT)
X-Received: by 2002:a37:5f41:: with SMTP id t62mr28794815qkb.410.1587581660554;
        Wed, 22 Apr 2020 11:54:20 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1587581660; cv=none;
        d=google.com; s=arc-20160816;
        b=MNgDb1HlPIGadVsIc5LTysU0m49bqQtSLPuc9BqhkafniqEj8tkLfZDZt5/Ghv0kkI
         HgNhQn11eh70zyPjb6pD42drj8kowZ/Go+7qjYwdIhQfABkqkJCaMLN5mBqfNcKrILEV
         LuSRlAliPhUkFXPN6IrPkJKikXjapVgfaq+tDdtUC/mP8jzvgsXieRfZNyMtc5ULLDT0
         KSHvbfdMJZgJ2/PLqTxtzNTgmHzPQFxPej1zVsI0AOsDfHvvGvVWCGEKDr/zs9GDcdGm
         Prn19ydGznEvx1suweYwnEy/7hwx5PDm+yVdkIv3UE/HscajmeBSyE9P/On01YpQBcJv
         ge2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:references:message-id:content-transfer-encoding:cc:date
         :in-reply-to:from:subject:mime-version:dkim-signature;
        bh=Cf7V5KoTnxdr5/vwnYfKOK1hbcf2VCNupE2mGkiuZek=;
        b=nkP0320IZCxdhFu2w6wcvfRILVPJkiX0KDB+95y8GPBpzvyfL4XPk5pctYBcjB4uog
         Tsb02TcOcR/AYG7F+aqQO1xvH9JLsiJHxXRzBF4iBNhPU72DzTKHRCOwMXB/6n+LLHzg
         hcy9eGMXPN18oaJ2h5IcVi+kLbqvFmcnSAe767iTSfFgiP7TmpkYm9Yaiaj2MUE+ofaU
         +l/F6c9ZXXcjZCbelmbJbr3IUjX6Yny0CpH9hcLf17Gen5ylC0eu4LBKGwN7q2Uaet2N
         G0CbA1BITr2krATFL/QkrpKKXDenxgSjNW7ylj842Eb7zwLchGbdg8WhjE9pH1R6R0lY
         4Z+A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=KcTXmBwo;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qk1-x744.google.com (mail-qk1-x744.google.com. [2607:f8b0:4864:20::744])
        by gmr-mx.google.com with ESMTPS id 140si10476qkk.1.2020.04.22.11.54.20
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Wed, 22 Apr 2020 11:54:20 -0700 (PDT)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as permitted sender) client-ip=2607:f8b0:4864:20::744;
Received: by mail-qk1-x744.google.com with SMTP id s188so2802219qkf.0
        for <kasan-dev@googlegroups.com>; Wed, 22 Apr 2020 11:54:20 -0700 (PDT)
X-Received: by 2002:a37:4c4d:: with SMTP id z74mr27822914qka.53.1587581660096;
        Wed, 22 Apr 2020 11:54:20 -0700 (PDT)
Received: from [192.168.1.153] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id c41sm29245qta.96.2020.04.22.11.54.18
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 22 Apr 2020 11:54:19 -0700 (PDT)
Content-Type: text/plain; charset="UTF-8"
Mime-Version: 1.0 (Mac OS X Mail 13.4 \(3608.80.23.2.2\))
Subject: Re: AMD boot woe due to "x86/mm: Cleanup pgprot_4k_2_large() and
 pgprot_large_2_4k()"
From: Qian Cai <cai@lca.pw>
In-Reply-To: <20200422164703.GD26846@zn.tnic>
Date: Wed, 22 Apr 2020 14:54:18 -0400
Cc: Christoph Hellwig <hch@lst.de>,
 "Peter Zijlstra (Intel)" <peterz@infradead.org>,
 x86 <x86@kernel.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
Content-Transfer-Encoding: quoted-printable
Message-Id: <48A05550-75AD-40EA-921E-BAE43453AC47@lca.pw>
References: <20200422161757.GC26846@zn.tnic>
 <59604C7F-696A-45A3-BF4F-C8913E09DD4C@lca.pw>
 <20200422164703.GD26846@zn.tnic>
To: Borislav Petkov <bp@alien8.de>
X-Mailer: Apple Mail (2.3608.80.23.2.2)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=KcTXmBwo;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::744 as
 permitted sender) smtp.mailfrom=cai@lca.pw
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



> On Apr 22, 2020, at 12:47 PM, Borislav Petkov <bp@alien8.de> wrote:
>=20
> On Wed, Apr 22, 2020 at 12:35:08PM -0400, Qian Cai wrote:
>> The config has a few extra memory debugging options enabled like
>> KASAN, debug_pagealloc, debug_vm etc.
>=20
> How about you specify exactly which CONFIG_ switches and cmdline options
> you have enabled deliberately? I can rhyme up the rest from the .config
> file.

The thing is pretty much the same debug kernel config has been used for
a few years, so I don=E2=80=99t deliberately enable anything today.

The best bet is probably to skim through the =E2=80=9CKernel hacking=E2=80=
=9D section of
the config and enable whatever you feel relevant if you have not enabled
already.

The cmdline is also in the .config via CONFIG_CMDLINE.

>=20
> Full dmesg would be good too, sent privately's fine too.

https://cailca.github.io/files/dmesg.txt

First, it comes with the dmesg that crashes and followed by the good dmesg
after reverting the commits (starting from line 644).

--=20
You received this message because you are subscribed to the Google Groups "=
kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an e=
mail to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/=
kasan-dev/48A05550-75AD-40EA-921E-BAE43453AC47%40lca.pw.
