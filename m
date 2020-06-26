Return-Path: <kasan-dev+bncBDIPVEX3QUMRBS553D3QKGQEXIIPNYA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pg1-x53d.google.com (mail-pg1-x53d.google.com [IPv6:2607:f8b0:4864:20::53d])
	by mail.lfdr.de (Postfix) with ESMTPS id EF45D20B5B3
	for <lists+kasan-dev@lfdr.de>; Fri, 26 Jun 2020 18:14:04 +0200 (CEST)
Received: by mail-pg1-x53d.google.com with SMTP id 21sf6920139pgk.9
        for <lists+kasan-dev@lfdr.de>; Fri, 26 Jun 2020 09:14:04 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1593188043; cv=pass;
        d=google.com; s=arc-20160816;
        b=CqBRuP0SugTI/vGHPO+Qbi1AGRaVWWuYgCdu2QZr3ayKIp5EFe5oXf+igMiIJOrU42
         Q4PmadmqmtM1WJzsScTbGPNaiuW/ykiWAP7n2VM5QKybDT6/rh4hJHWBdIedA6a0h1/P
         GEIGKrQMyjBYzWu0BQUUVEjt1CWV/UJqExfoMefPZwUEJlVMlJm/wDT7dU4vWMoXMuFy
         Z5aU9XETcvcKR3U1yjosqU1N5dt9aGDRans1WOgz9DVOxGqD767jb396bfcerW2UCOaS
         lj/8L8f2HilLgQD09r6udZ1Axggs4Wp4qkNtVF3DzpIMmMluljlMfvDu+n/oFE4aKnPK
         +X/A==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:organization
         :references:in-reply-to:message-id:subject:cc:to:from:date:sender
         :dkim-signature;
        bh=EuB9XnLUuZfHfZDGkhFbP/k+elmMEh1VUM7FsyYWLEw=;
        b=KuF81NPUX0qqXbGzdHsRp1bzvB4nBRcuDW11bbC5EcsPTaGdGzUDwyk/rWta1GEjOD
         4/ed/3HOPFWpojf53IjwdqL1fe7XnL10pBAwc4Z3vTvBzrBPHcqMbf6p4Rak/vZK7WRt
         0Co8lOia0SGf9ctpUkkDkLphcluf+KMAB1B4NNhgcYXoQic32Bg76kOOGqaYInh0bzU1
         14p0BktmNErkNOdoqLPV7XIJHz6asm6hzjwmEKYdb8G4jhgcfTzfqsaQblXDr1EmEknQ
         ze2IWqULGj3j7RT8EE4UDq+FoS9Y4I1or+LbDP+JDGTkHKDgpSVdTjquLlTFMqt5ZADS
         UAzw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:date:from:to:cc:subject:message-id:in-reply-to:references
         :organization:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=EuB9XnLUuZfHfZDGkhFbP/k+elmMEh1VUM7FsyYWLEw=;
        b=Px1hVOKKIXMnETuvR+D2luEZt1ccgF+rolBpQEkZKYB8TzpdWOh3jDwHChAkDi5p1G
         O9/4p128ugQ2R3YoHT3LnxQMhs/80N9z6zHYVwy2tT9/B+H7RqccK+9lU2KNRko64Ic9
         wru+VZHNR3jIiQ00y7hM+5WnmsY0JCeNb0GJwPvDSiTHgKfstbSA1FKXCZgH57ulT450
         NmIalhyvn30pze7x0PVf3ixR592UWOH12InEt3ONUg9qKkv26C1NSNtdGaLLwJsBl2d0
         RQAuIblQiimaCMY1tYBBusloLy37kpTgBmsyrPQ8RclsojY+KEP9dWrlCkUC/hY1i2om
         liQg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:date:from:to:cc:subject:message-id
         :in-reply-to:references:organization:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=EuB9XnLUuZfHfZDGkhFbP/k+elmMEh1VUM7FsyYWLEw=;
        b=W8GAwiY8egE1zcmvvpmxnUKVkTi0w62Jr/PSHB5mGZzKHVpSq9/SRMgAjrVbCa1mQA
         9gMbCNXZLgmQvv8UiP8g+9WDIiWeOfwnDOHIyHfQ1HPvXnFZ9cIc3lJYRWOTGGeCZZOs
         IUNT7m+Ruk02W8eVV1XaX4paxBHYEZugSZFoNTJgK+pO5mA9+oH492pCsLRyxxrAjXjz
         Tv08gSPj+07IwQ9vNVBJvGVQq7sNIAjLKFwGWtx+O/q+PN/sfj7o06ERXPcRolVjJVTs
         qZmSj7oGOnwHvjhAR8YYD4oV9CgFeBZDT4en4BKwFVpWhfdMWseJVNZvzpNsr3dQgoUx
         mFAA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532NAw8avfib0SW8sqkEZGgPdltmWiQwysynxGGg7DKIUvmsUYZR
	aqXfqA7XaTb81XYtYJJR8Es=
X-Google-Smtp-Source: ABdhPJx6gzP+LKnzUWgWgKJo46WFr5WQTLhMcDT+uecslIXc+aEC7nB+Th0yxdq7gzyOcU4eHb9ezg==
X-Received: by 2002:a63:d958:: with SMTP id e24mr3483817pgj.348.1593188043483;
        Fri, 26 Jun 2020 09:14:03 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:902:7686:: with SMTP id m6ls3701161pll.1.gmail; Fri, 26
 Jun 2020 09:14:03 -0700 (PDT)
X-Received: by 2002:a17:90a:db87:: with SMTP id h7mr4558520pjv.159.1593188043079;
        Fri, 26 Jun 2020 09:14:03 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1593188043; cv=none;
        d=google.com; s=arc-20160816;
        b=XzZ4wCzi528cmeB9wTUDjMXWcYzUGWKuQ2SPX+mzH45cjp2JyW++5yDG8nfppff/33
         8FanJ77SbLkA7LafWXo0h99okjyqTIlcNGGu/Qgyt5SSIG90/E67iwBqYr2CV+eeQ5Kl
         0XlgLjK1iTLli04kCaSTvZue/pQhoI8/yQR0nJGpjtM1yyvCjwhV5NRAynJr1ARS2POL
         nLYXt7B5BV/9WYk4puuwYWNTfKd+2Y7R78P5YRsLnQeZlRMQRjx3OkqZvjI2rdyWheel
         g6S4HlIFHStnZexZ9tRmq8SXmmkLDAVOkafWiM3g8/CindG2UL4tvULfVu6GGWbor5eC
         GaVg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:organization:references
         :in-reply-to:message-id:subject:cc:to:from:date;
        bh=KyI34ojyx5h0uNQHDj1OldCGEi/k0atOH8X+XYa2U5Y=;
        b=DU5rtI2hHDEQdQN61yog6Gp6y4x9ajUk29I7J8SlnjByAvoFrVTynQUA0LZnNVC56U
         sPvhBgzpKsZGMpr1sB1N5slg+MCLzDsQyD0gKpP4n6IXZUMOgPTPU5M/0C8c088R5/1Z
         XdO4uZDQOnOstSQmJEFELTzY10Ob6s/EaRTZB2ta4QQjpp9YYZX73wzo3NLJYK86oWDf
         cL1AXXd0RoIHGolbT/hE9VmJ6Mj0tsVw6NVDbRp1BWHU+ecgIGfDeckwo7Suol1oIrrp
         In1UiStEQMearKg9CkbICUHUL4KUIBTkUtK8d3GI6M2bjeZ0Sj6IVXHFi7WEpD19i4eO
         yB7Q==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) smtp.mailfrom=corbet@lwn.net
Received: from ms.lwn.net (ms.lwn.net. [45.79.88.28])
        by gmr-mx.google.com with ESMTPS id kb2si72292pjb.1.2020.06.26.09.14.02
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Fri, 26 Jun 2020 09:14:02 -0700 (PDT)
Received-SPF: pass (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted sender) client-ip=45.79.88.28;
Received: from lwn.net (localhost [127.0.0.1])
	(using TLSv1.2 with cipher ECDHE-RSA-AES256-GCM-SHA384 (256/256 bits))
	(No client certificate requested)
	by ms.lwn.net (Postfix) with ESMTPSA id DCE73374;
	Fri, 26 Jun 2020 16:13:59 +0000 (UTC)
Date: Fri, 26 Jun 2020 10:13:58 -0600
From: Jonathan Corbet <corbet@lwn.net>
To: Mauro Carvalho Chehab <mchehab+huawei@kernel.org>
Cc: Linux Doc Mailing List <linux-doc@vger.kernel.org>,
 linux-kernel@vger.kernel.org, Ram Pai <linuxram@us.ibm.com>,
 linux-mm@kvack.org, "James E.J. Bottomley"
 <James.Bottomley@HansenPartnership.com>, Eric Dumazet
 <edumazet@google.com>, Benjamin Herrenschmidt <benh@kernel.crashing.org>,
 linux-ia64@vger.kernel.org, Shuah Khan <shuah@kernel.org>, Tony Luck
 <tony.luck@intel.com>, Andrew Morton <akpm@linux-foundation.org>, Sandipan
 Das <sandipan@linux.ibm.com>, Fenghua Yu <fenghua.yu@intel.com>, Florian
 Fainelli <f.fainelli@gmail.com>, Christoph Hellwig <hch@lst.de>,
 iommu@lists.linux-foundation.org, Alexey Gladkov
 <gladkov.alexey@gmail.com>, linux-fsdevel@vger.kernel.org, Bjorn Helgaas
 <bhelgaas@google.com>, Sukadev Bhattiprolu <sukadev@linux.ibm.com>,
 linux-pci@vger.kernel.org, linuxppc-dev@lists.ozlabs.org, "H. Peter Anvin"
 <hpa@zytor.com>, Akira Shimahara <akira215corp@gmail.com>, Ingo Molnar
 <mingo@redhat.com>, Dmitry Vyukov <dvyukov@google.com>, Will Deacon
 <will@kernel.org>, Dave Hansen <dave.hansen@intel.com>, Robin Murphy
 <robin.murphy@arm.com>, Kees Cook <keescook@chromium.org>, "David S.
 Miller" <davem@davemloft.net>, Marek Szyprowski <m.szyprowski@samsung.com>,
 Jan Kara <jack@suse.cz>, x86@kernel.org, linux-kselftest@vger.kernel.org,
 linux-media@vger.kernel.org, Greg Kroah-Hartman
 <gregkh@linuxfoundation.org>, "Eric W. Biederman" <ebiederm@xmission.com>,
 Gerald Schaefer <gerald.schaefer@de.ibm.com>, netdev@vger.kernel.org, Jeff
 Layton <jlayton@kernel.org>, Paul Mackerras <paulus@samba.org>,
 linux-parisc@vger.kernel.org, Haren Myneni <haren@linux.ibm.com>, Marco
 Elver <elver@google.com>, kasan-dev@googlegroups.com, Thomas Gleixner
 <tglx@linutronix.de>, Michael Ellerman <mpe@ellerman.id.au>, "Peter
 Zijlstra (Intel)" <peterz@infradead.org>, Mike Kravetz
 <mike.kravetz@oracle.com>, Alexander Viro <viro@zeniv.linux.org.uk>,
 Borislav Petkov <bp@alien8.de>, Alexey Dobriyan <adobriyan@gmail.com>,
 Thiago Jung Bauermann <bauerman@linux.ibm.com>, Russell King
 <linux@armlinux.org.uk>, Jakub Kicinski <kuba@kernel.org>, Stephen Rothwell
 <sfr@canb.auug.org.au>, Helge Deller <deller@gmx.de>
Subject: Re: [PATCH v2 00/15] Documentation fixes
Message-ID: <20200626101358.6efc4f8f@lwn.net>
In-Reply-To: <cover.1592895969.git.mchehab+huawei@kernel.org>
References: <cover.1592895969.git.mchehab+huawei@kernel.org>
Organization: LWN.net
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: corbet@lwn.net
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of corbet@lwn.net designates 45.79.88.28 as permitted
 sender) smtp.mailfrom=corbet@lwn.net
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

On Tue, 23 Jun 2020 09:08:56 +0200
Mauro Carvalho Chehab <mchehab+huawei@kernel.org> wrote:

> As requested, this is a rebase of a previous series posted on Jan, 15.
> 
> Since then, several patches got merged via other trees or became
> obsolete. There were also 2 patches before that fits better at the
> ReST conversion patchset. So, I'll be sending it on another patch
> series together with the remaining ReST conversions.
> 
> I also added reviews/acks received.
> 
> So, the series reduced from 29 to 15 patches.
> 
> Let's hope b4 would be able to properly handle this one.

Nope.  I don't know what it is about your patch series, but b4 is never
able to put them together.

I've applied the series except for #1, which already went through the -mm
tree.

Thanks,

jon

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200626101358.6efc4f8f%40lwn.net.
