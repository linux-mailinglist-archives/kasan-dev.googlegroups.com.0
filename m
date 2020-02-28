Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBVPT4PZAKGQE22DXSLI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yw1-xc38.google.com (mail-yw1-xc38.google.com [IPv6:2607:f8b0:4864:20::c38])
	by mail.lfdr.de (Postfix) with ESMTPS id 56A3B173608
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 12:30:31 +0100 (CET)
Received: by mail-yw1-xc38.google.com with SMTP id w197sf4266520ywd.17
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Feb 2020 03:30:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1582889430; cv=pass;
        d=google.com; s=arc-20160816;
        b=o3bPecnhPL36O70ojlCnvOLbD5z3AC7Q3xyl9jZtoTMGVqL2BrCGbFIbde9rwRCYyA
         MBvpo7OjmM2qQ6eL9R7Xfz90EcgCCc+7IiMFnXS38AjGLm/bq7FE740I7LslHts2Hubr
         KosA2wkShdj/eMmecZ366lX0fnpRS4LUy9ethnW6xewqyWLuAwz/lnKpALALg/7Og91y
         Xodxy/bDFaNcYSRDqCsgks9MV1/NF1XYRzXdqk9fjtoFurFlDK7uoIR9nHkcClZrP5/J
         n38v5M+Xp204+Jn/QWux91zsxWGzrRqlf65iZcBF1E5tw2TfaZaNIpyZz/BQzFwpTFGG
         wGuA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:cc:message-id:subject:date
         :mime-version:from:sender:dkim-signature;
        bh=h35TibKb/PwhxptMXBK3RRYJER/IQoEmyoo9djU8HCQ=;
        b=Y8/y+uB19euBsyqfGb7PbMa75wHTfby3brNpr3/Q7pYQgR6nB+zTgm+nukl4P7tdEh
         RXfVYsu6Fa+4ahMgEqpTdF+/ko7gU/wDBdY1/p2O71wGj9412RzU6stcH1v/BWXzAjCg
         phePw5ygrBcquLYOzYa5gKvM0rMIT1dJ2mFqK4nBrU7k/cSDMVXAk/V4NxHzW9TE912f
         Ur5pqryCuc52y//4WQQVt2sSbsuRdIcLmzzhVs6gY/AofOADiAXJq/qdwCEdgKbodZ23
         u6htbbsPjW0uEItk/gQU08bT6kovPV6smXduC9gq+QV6DHZ2WCNWlmOlODNw8wOa1urK
         qDxA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=UwLKK6xz;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:date:subject:message-id:cc:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=h35TibKb/PwhxptMXBK3RRYJER/IQoEmyoo9djU8HCQ=;
        b=Ki/S7b/DdKePC3kPMYd4fL/vzgVThPsDNF3OPhAF36LOpbWeZIUspZc3QhVpdIeeUY
         selMO4AQc0DHLVoTDtmIEzC91mzD5AvY+Z0JwsJ8RnIrFwtzQqdwxOqEn5ZLOrqtoVX5
         1ri1Jk2Y5VLwfNsLG1/K4PYeMRgtIFUZURXX/fI9QNrK7gT5gjC11HPa40x/3L+LQdpi
         dK2BtNdmQwG48UItXPHPF+yibx3Y9X6Xsi1/UJVFNotxKZFpN+mq06HkP90aIhNm6xHw
         tGcddy3qgrxDdGCEc5eVuIahTel8mM7tEKz6pQfP3S0a+NFp0dfXKDNRwW1wJaoa135W
         YTFQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:date:subject:message-id
         :cc:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=h35TibKb/PwhxptMXBK3RRYJER/IQoEmyoo9djU8HCQ=;
        b=XrRT4XXAadpwr1BWGoze183xHweukstBA7R9UjQHs/IxmGgXUhGAZhWH2grMr+RiDB
         xAWD2BEYIxcJK4bvm+0Hfgwz6ms+8xjcVst76gcQO4n1FGENPzn7ax9S4EElDIyHKIhU
         zcLERVhe1HhUeExVVesuqIbDPmyRqy2bPqF0n8n4OeBrDGmL6/56nMGIqyzcE41pKjGu
         SkILNVkNMGTKZzpIU7BFQjtCMrFtXlgDtIf6GhL7efsKz7ea13B4+a9FCy3rN7crSHYF
         HLULDSxJ9FBCl+PHu6vx4im0D3aruYgCEd5mW2xnTe+xaPraPWX37gExzUS3xL+R0XxW
         QgAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAUnrWiuzuG/3S3L5A47WM04lslC28p9qt39dP/xPP5S9ENJIuMn
	ZEr2goNQNV/b4y5KwHb61GI=
X-Google-Smtp-Source: APXvYqx3bhUho34jLeCHnG19+XnzDU/E/pvUtAWefip/erhUDMhJt8XyPcbnLk7qwNVyQZhGoM6HFw==
X-Received: by 2002:a81:70ce:: with SMTP id l197mr2424555ywc.448.1582889430155;
        Fri, 28 Feb 2020 03:30:30 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:d851:: with SMTP id p78ls629535ybg.3.gmail; Fri, 28 Feb
 2020 03:30:29 -0800 (PST)
X-Received: by 2002:a5b:792:: with SMTP id b18mr3122245ybq.23.1582889429729;
        Fri, 28 Feb 2020 03:30:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1582889429; cv=none;
        d=google.com; s=arc-20160816;
        b=f9585EwIl8qbNT2HD5JT5hMU/oOTrT4z1PuMN66DkdNwZ2+2RZG7CU2MiVt4W1LQJG
         Fyd9+VLIuUb5GF0yLoavMryO4bkyoY+mIcwEv9On6HYb48WZcOa9NMsDrlQi18OALe9I
         zcjtMisJqsdGfyfUoB7Zd6j0ovNWZcGXs8zqvZfMckThXvQLT39c1cX8RVjECCqEDGbr
         7eeP+LQ2xuSuR0LNQo98JKP4xD3UuzqZ28qOjMa7hj04mT4BFsl2KxT9donA4XdBkXoI
         vb4E8ph1ojnvEvlKR5w8KFlsARXSoDFK7BVkLJOTNIBjbVVF8xZxmoYEoEPOYyvWeNE+
         dUGg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:cc:message-id:subject:date:mime-version:from
         :content-transfer-encoding:dkim-signature;
        bh=TyGvF4gDQhRWGSQu6uFitGsvvO6sV6I67VJLT7zuiLc=;
        b=IuQ62u+D3UNzI4HtN6kYJf6GqtyIBMzl0V55giMnGSscJV3ftSWif5PVmJAJi3VH57
         S+GOYv4hV5y68WHCHPgyhJBbrX3FpNI24kmWelwQK6Xt6joddx8o0NjM1Q5SrmjnmXPn
         q6SMTf/bc+pfz+3E6tfKnmB6lCpTkTNsPzU6PukRDbJRJlvHBbTiAPRJ3VF6rbyOeTc7
         heVsJhr0Df3VhYw31f0HlZHpB+Uo2jL8nin9I5U21B+RSuvXnEX1IHkwT3+Y2Zdcm7nS
         Be+dnwAaMNNHJxfn1kc+1hhxMwgHXyi7IEhcGxTYJoricC8jsw/6xOxH2/FCyXiv/GjO
         wG+g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=UwLKK6xz;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x842.google.com (mail-qt1-x842.google.com. [2607:f8b0:4864:20::842])
        by gmr-mx.google.com with ESMTPS id d80si226407ywb.2.2020.02.28.03.30.29
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 03:30:29 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as permitted sender) client-ip=2607:f8b0:4864:20::842;
Received: by mail-qt1-x842.google.com with SMTP id j34so1741808qtk.4
        for <kasan-dev@googlegroups.com>; Fri, 28 Feb 2020 03:30:29 -0800 (PST)
X-Received: by 2002:ac8:9e:: with SMTP id c30mr3800792qtg.359.1582889428464;
        Fri, 28 Feb 2020 03:30:28 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id a6sm3438231qkn.104.2020.02.28.03.30.27
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Fri, 28 Feb 2020 03:30:27 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Date: Fri, 28 Feb 2020 06:30:26 -0500
Subject: Re: [PATCH] mm/swap: annotate data races for lru_rotate_pvecs
Message-Id: <463BBB2A-8F9A-4CF1-80AE-677ACD21A3C6@lca.pw>
Cc: Andrew Morton <akpm@linux-foundation.org>,
 Linux Memory Management List <linux-mm@kvack.org>,
 LKML <linux-kernel@vger.kernel.org>,
 kasan-dev <kasan-dev@googlegroups.com>
To: Marco Elver <elver@google.com>
X-Mailer: iPhone Mail (17D50)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=UwLKK6xz;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::842 as
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



> On Feb 28, 2020, at 5:49 AM, Marco Elver <elver@google.com> wrote:
> 
> Note that, the fact that the writer has local interrupts disabled for
> the write is irrelevant because it's the interrupt that triggered
> while the read was happening that led to the concurrent write.

I was just to explain that concurrent writers are rather unlikely as people may ask.

> 
> I assume you ran this with CONFIG_KCSAN_INTERRUPT_WATCHER=y?  The
> option is disabled by default (see its help-text). I don't know if we
> want to deal with data races due to interrupts right now, especially
> those that just result in 'data_race' annotations. Thoughts?

Yes, I somehow got quite a bit clean runs lately thanks to the fix/annotations efforts for the last a few weeks (still struggling with the flags things a bit), so I am naturally expanding the testing coverage here.

Right now the bottleneck is rather some subsystem maintainers are not so keen to deal with data races (looking forward to seeing more education opportunities for all), but the MM subsystem is not one of them.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/463BBB2A-8F9A-4CF1-80AE-677ACD21A3C6%40lca.pw.
