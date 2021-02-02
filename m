Return-Path: <kasan-dev+bncBCT453EYWEJBBNUJ42AAMGQEVZM27CQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-lj1-x239.google.com (mail-lj1-x239.google.com [IPv6:2a00:1450:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 5ECB630C6AC
	for <lists+kasan-dev@lfdr.de>; Tue,  2 Feb 2021 17:58:31 +0100 (CET)
Received: by mail-lj1-x239.google.com with SMTP id c1sf8074838ljj.8
        for <lists+kasan-dev@lfdr.de>; Tue, 02 Feb 2021 08:58:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1612285111; cv=pass;
        d=google.com; s=arc-20160816;
        b=09GTISCcYD0inl+PyeR3+v9bSNa7b9ar5GqcEWm3L9lddZlErWMayh7wX0BqugO7g3
         EX3kGEBzNOcgQZsPJ1T0CB2qbCO8FoyD6h/FRMMlhxRZzf+7yUHPSUtNRlQGJ5N78OOC
         UQCa+FpSIC8Je0H7lTbefq5rTh2XhsaguGf7B9DqzMa4ja4ozkpkhomMP594yuRd/pRM
         aExlZ5DT7RJBJQvmx6h58x9w8Q5dz2YCYkwXRWtLA4OlEq7r3u8QMSI7RlJ2rCVLETHC
         +QXfNqkFSQPbcQsCX4TgufAC0lOt2HbvTAJrJh50FsdCrDKxccJrWJod/3Bxw5WnDMAm
         0KFQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:cc:to:subject:message-id:date:from
         :in-reply-to:references:mime-version:sender:dkim-signature
         :dkim-signature;
        bh=cnUuTH3LoE2uWDcjEFG3ynnedYHI6S4bJ8X0eqZB4Qo=;
        b=A73Fj5Q4zVAGmfrQF6rGSeNFP5SdWHqkl87maVltBKmQUOLZqqQ6bFS2183H8tKbCy
         KJw9ifY9ELz/md+6tXFxj1Lu/EPuv2LPav3ZzlmYfx3+R/bz5dpaMeOcrp4Y083061SA
         OrN3+Cac0J8iJg/8fIxs8twGMrIcB2JEr5ZX8LfGY341iy088Kzyk1BWFHZWyNXaDJbv
         ai47lNK2a6BTKkJe16SBoGys5wS5TiY321nDMo+u6FPq5O7P6WPXprTscUGdPiSOTsFI
         bnpOiUMC1vahJwp253+uHIWsvEETZ25NjNO+kZInjMj1oiN7oQVpnhKQfDxuf+RzBNqb
         4LiA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=O2iZQSgf;
       spf=pass (google.com: domain of christoph.paasch@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=christoph.paasch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:references:in-reply-to:from:date:message-id
         :subject:to:cc:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cnUuTH3LoE2uWDcjEFG3ynnedYHI6S4bJ8X0eqZB4Qo=;
        b=Ere98vQTSBC6Gafjid6FZgpAJYxNeEBjg+G/RZuu2spWYbixVw3BuAhP6pspwQVZE9
         Xous9SXQOYJoXIr9NOiC9Ara176fs2tfke4RHLJfEDJi/Nqg7U5mgSFHmYhxKEsY3yIS
         vf37m7K6kURmeR3WsCHPj3QtRCT39btmH+03Fe8PYSJQ3Flawy7rcLNltbPygUfIFh2s
         bK3xsvERBS0B1/2STbBJaLp7kZmfeXUndGJ5oyn/S/NUUrW8FIYZ/uedsckaGPsEdQdK
         F+MtILN2Yi64X0lDt84JfoBOkQG/W7uLGRhOJBZdr9drSdlT2Kg1gxQauMqpDJUi2kUV
         AycA==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:references:in-reply-to:from:date:message-id:subject:to
         :cc:x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cnUuTH3LoE2uWDcjEFG3ynnedYHI6S4bJ8X0eqZB4Qo=;
        b=PBjm/WpO1I94MDmQh4Lfss+cWnpj/B2idkpiDX5xN3F4FDEpZny1M1iUVimVRCngtl
         y9KKkuf6fljya3FCK73WmhlZUK3gVcpfM/qLjvoiB93rHocRC+VWl/8AR7DzswZBeGrU
         0q9SxlWMi2onC4Tm7nDjQY8BOJ09jjvPDmNx6CQajLVf+YCzDKjFrGS/kNp97INcj12F
         a4Cu55lSwjXlGeJ6UTKQZECjK2CiIQ5Iwipha9KOlg7yjFUkFImuLEwI11t/PJ1ra46U
         mQQXGJPb1yll/V3TDqz6IdNldflF/Qq0qQCeZupGuSSBIjt+AbStbWy8FEd4aQU2B7Lo
         8IIQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:references:in-reply-to:from
         :date:message-id:subject:to:cc:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=cnUuTH3LoE2uWDcjEFG3ynnedYHI6S4bJ8X0eqZB4Qo=;
        b=pgJ8fPou/gKU6ayeeci/6r+yPSQtzyIED6c6LURO+ZbcLTmOAzxJi+Iyblh3NMO9Zk
         +AgGQY5xdp+hgVkvfNHQd20XjKyljsZGinqgffCmtMC2hAx5gTXrUw3Jo2l6bzm/8iSe
         Z/4fanC9ZNDai9NPFuSP5TcnD/FBoU9ZkTsORqNrsy/EjHT3x+bvTTIjXD8jjWJy3YvN
         VZdvEzS9ASxdqpDYtssHCNNwn0HYkduo+cTc+GGhcQhrZFlhtzAARMEB04Ri/Xx+swSH
         JNuCeF661kN0VH2PyGmzPLPoVcGO+A4aAPDWTOXJe4YGDeihCkrJ7u592oFPXGjiDhN9
         ZTSA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533SUhdogiLYhgbSL7oA0UX21wMqeNiVuIPRmlcNT44lj5h7uizt
	DCRffMBXs3Ao61lkhA5yhhI=
X-Google-Smtp-Source: ABdhPJykflLgj0/ah0lHSDDqopSxNCePEjC58wnMk/6S6Dte5hDIVWytJ94a/SMoBIikiOfiwDTlUw==
X-Received: by 2002:a2e:93d7:: with SMTP id p23mr13622672ljh.271.1612285110965;
        Tue, 02 Feb 2021 08:58:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ac2:4adc:: with SMTP id m28ls3590469lfp.0.gmail; Tue, 02 Feb
 2021 08:58:29 -0800 (PST)
X-Received: by 2002:ac2:5312:: with SMTP id c18mr11807283lfh.318.1612285109865;
        Tue, 02 Feb 2021 08:58:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1612285109; cv=none;
        d=google.com; s=arc-20160816;
        b=t/4EOrFojlAKo1rxGDYZB8jgiVbzlE8F7b/Yu5442MBmpZmxpZ6gliCqF2GOXaFfHI
         oVQFhF67VfoS0wZPWeaZ7RbuXiA4SJrfNGU515/QbvL/S8NEx1YUkuzHWetOEqiVqAvz
         XPTrvfSoScBjkg5KQ2LmJ+kVZYRUq5vdFDBMaVr+NCimOOcQt+mzt2N6nj5ud/syCIRK
         MSeB0Xlvbmh3DUyz6v2Aw5P0eMMNks6gAc+1NnfpJt8J60v3rfXw7vNb8nb5yrPZ+LrY
         zbeWSMTlE5m/EDJKAFYdDw+fj5Kg3U9bwg8U5Dq2JE8f+qzPhrXI+dv7KLEqYgw5fPp5
         1A2Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=cc:to:subject:message-id:date:from:in-reply-to:references
         :mime-version:dkim-signature;
        bh=QoFBWNVeW362Fh0rp8McJnSuJrL1LHsgZ+i7Ga7Dn18=;
        b=ve+04UtB85g7lG0Q1iTA4G5e7VXcEpqkx941nJJVgrMWwn2UWyOCvYqfI79YGTxg49
         9E/tK0Ta4eoYv0QEtC/AfKj5r0XLn+HoJ1oLiq5zT6xfLXlGOgOKa1jqf/WPdDAz9ag/
         prJ+E32aiB+UK7iYgVsFrkAitDYngbRvJGFb00Rs5eDq+huCvdaRb2Iq+6qBFMzogjVt
         z2guCt1ItsOBpIH2hwzvqRoqkOTR1hrfA2wRp/FoTX0Wm6npexSc46mew5fFp8IIx3m9
         SgqK3G/2OmcTrazziAUckk54KVr8JAdY+BtRTh01Lgzd6fyRu/knX/kKd5zDDQOSy2cL
         DyMA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=O2iZQSgf;
       spf=pass (google.com: domain of christoph.paasch@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=christoph.paasch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-ej1-x62b.google.com (mail-ej1-x62b.google.com. [2a00:1450:4864:20::62b])
        by gmr-mx.google.com with ESMTPS id s5si26225ljg.7.2021.02.02.08.58.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 02 Feb 2021 08:58:29 -0800 (PST)
Received-SPF: pass (google.com: domain of christoph.paasch@gmail.com designates 2a00:1450:4864:20::62b as permitted sender) client-ip=2a00:1450:4864:20::62b;
Received: by mail-ej1-x62b.google.com with SMTP id lg21so3721576ejb.3
        for <kasan-dev@googlegroups.com>; Tue, 02 Feb 2021 08:58:29 -0800 (PST)
X-Received: by 2002:a17:906:b0c2:: with SMTP id bk2mr23572150ejb.223.1612285109601;
 Tue, 02 Feb 2021 08:58:29 -0800 (PST)
MIME-Version: 1.0
References: <20210201160420.2826895-1-elver@google.com> <CALMXkpYaEEv6u1oY3cFSznWsGCeiFRxRJRDS0j+gZxAc8VESZg@mail.gmail.com>
 <CANpmjNNbK=99yjoWFOmPGHM8BH7U44v9qAyo6ZbC+Vap58iPPQ@mail.gmail.com> <CANn89iJbAQU7U61RD2pyZfcXah0P5huqK3W92OEP513pqGT_wA@mail.gmail.com>
In-Reply-To: <CANn89iJbAQU7U61RD2pyZfcXah0P5huqK3W92OEP513pqGT_wA@mail.gmail.com>
From: Christoph Paasch <christoph.paasch@gmail.com>
Date: Tue, 2 Feb 2021 08:58:18 -0800
Message-ID: <CALMXkpbpB7AWNvtH4dbgP_uFi0hV8Zg0JfPkkdOLFwLRvxGMPg@mail.gmail.com>
Subject: Re: [PATCH net-next] net: fix up truesize of cloned skb in skb_prepare_for_shift()
To: Eric Dumazet <edumazet@google.com>
Cc: Marco Elver <elver@google.com>, LKML <linux-kernel@vger.kernel.org>, 
	kasan-dev <kasan-dev@googlegroups.com>, David Miller <davem@davemloft.net>, 
	Jakub Kicinski <kuba@kernel.org>, Jonathan Lemon <jonathan.lemon@gmail.com>, 
	Willem de Bruijn <willemb@google.com>, linmiaohe <linmiaohe@huawei.com>, 
	Guillaume Nault <gnault@redhat.com>, Dongseok Yi <dseok.yi@samsung.com>, 
	Yadu Kishore <kyk.segfault@gmail.com>, Al Viro <viro@zeniv.linux.org.uk>, 
	netdev <netdev@vger.kernel.org>, Alexander Potapenko <glider@google.com>, 
	syzbot <syzbot+7b99aafdcc2eedea6178@syzkaller.appspotmail.com>
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: christoph.paasch@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=O2iZQSgf;       spf=pass
 (google.com: domain of christoph.paasch@gmail.com designates
 2a00:1450:4864:20::62b as permitted sender) smtp.mailfrom=christoph.paasch@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
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

On Mon, Feb 1, 2021 at 9:58 AM Eric Dumazet <edumazet@google.com> wrote:
>
> On Mon, Feb 1, 2021 at 6:34 PM Marco Elver <elver@google.com> wrote:
> >
> > On Mon, 1 Feb 2021 at 17:50, Christoph Paasch
>
> > > just a few days ago we found out that this also fixes a syzkaller
> > > issue on MPTCP (https://github.com/multipath-tcp/mptcp_net-next/issues/136).
> > > I confirmed that this patch fixes the issue for us as well:
> > >
> > > Tested-by: Christoph Paasch <christoph.paasch@gmail.com>
> >
> > That's interesting, because according to your config you did not have
> > KFENCE enabled. Although it's hard to say what exactly caused the
> > truesize mismatch in your case, because it clearly can't be KFENCE
> > that caused ksize(kmalloc(S))!=ksize(kmalloc(S)) for you.
>
> Indeed, this seems strange. This might be a different issue.
>
> Maybe S != S ;)

Seems like letting syzkaller run for a few more days made it
eventually find the WARN again. As if Marco's change makes it harder
for us to trigger the issue.

Anyways, you can remove my "Tested-by" ;-)


Christoph

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CALMXkpbpB7AWNvtH4dbgP_uFi0hV8Zg0JfPkkdOLFwLRvxGMPg%40mail.gmail.com.
