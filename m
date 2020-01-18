Return-Path: <kasan-dev+bncBCD3NZ4T2IKRBQOMRPYQKGQEII6RLAY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-il1-x138.google.com (mail-il1-x138.google.com [IPv6:2607:f8b0:4864:20::138])
	by mail.lfdr.de (Postfix) with ESMTPS id 8E99F14171E
	for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 12:04:34 +0100 (CET)
Received: by mail-il1-x138.google.com with SMTP id j21sf21029298ilf.16
        for <lists+kasan-dev@lfdr.de>; Sat, 18 Jan 2020 03:04:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1579345473; cv=pass;
        d=google.com; s=arc-20160816;
        b=TFnLJc8pUbvCJp15hrwUsPd5mG3VYhsLNXMxnQ5jWa4ii5gco7xGsyECUvrrLrxN6B
         RrtSIxSliCvgvoPjxl1ayTJyv12dmi5j0PpZU2iXhidc34RUiYfmz07VEh5N2WYBxVzA
         bLLT/sbr2GdpAgoH5r0XKcYLfs2iA4uMmSzvRkcbBaIdPMHUsDiftXsO3CYIAjH8Yl/Z
         z0gOlsYW44LIBF018XUKLiDUleAGhUI4AqvFHOAMeCu8ljvMnS5y5u6WutuloZp6l6IP
         j8WXy5To5Z65l89Awu5LMzIfPpzHD57H9NeBs2JXnNJZR5RthzJNUL1un3ecHrKN4kr/
         vvqg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:in-reply-to:cc:references
         :message-id:date:subject:mime-version:from:sender:dkim-signature;
        bh=iOJXI+lMGdi4JqVAsgrSbaTR1C/kiSVag2eajkl5d6c=;
        b=UedLXDex89BOkHwSSfk6VSSgJP+SIZM5NloohqLJzLG9cFUN3Uk0mFVg1hFwcqf562
         9KNxmlz9nXfFgA8pFwXCqtF8ilIhxvKpUL6XfnIm+8xuJzTht/iriUiYRAsq0kC28hkL
         5Os2aOJ0a5tUWAkusPlRFdc83YyS7wp1/8xp7X9SkVDhzdz2jlB7vye1T6gl7G351eoE
         NgbF9gjNsKIdKD1l9lH/AFPny2qTXOLbwSzZqloe2mBoz+uDv4/WinNUFOIjDpg4MG2r
         pL0MLLcyLcXUs4buJKkH3LISnMsErBuLyXxGpPjjrj99fxFsYg/XQOA3PhsT7W7Ukmzn
         TG3Q==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=d6JswzAO;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=cai@lca.pw
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:mime-version:subject:date:message-id:references:cc
         :in-reply-to:to:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOJXI+lMGdi4JqVAsgrSbaTR1C/kiSVag2eajkl5d6c=;
        b=kruO5iDSBuOnSifXanjIOBCpFUUPVVMiMwCwDd2jTC3DmMyagthAqs/7Ay72kr6Vo2
         FpU2CezIdYJRttPs7Y71HpSsJqxBEKEBQ8PvHGImNyWN96bSGKFULArV4evrKdK09EAH
         5LW2Pa3Y+OyXtZ8UlEFSsEfkdEt+YhGUXfQQBm5kRHhfhWweOvxsTFPEbdtygFjPm3RY
         x64dYiSoSc/ybGyF2gvkOEa5RcTdJoQ5BM+Td8sfPm01BxeUgVI3683g+8unuTvwNY+x
         P4Ya9QnkcjZ14FsyLaAyfWoeX4P959mGJhFSFgbZ/ul+LTa2GU0O6/xxr/kUgRXBye+5
         EJmQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:mime-version:subject:date:message-id
         :references:cc:in-reply-to:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=iOJXI+lMGdi4JqVAsgrSbaTR1C/kiSVag2eajkl5d6c=;
        b=nWednoo/olAlzW4LddlqTw/JlHNvyRZIQRc3oyDPl2k44oJLg2JyHtXnYw1bk33eKX
         Pk94p4n5Dxw4752dr+u43KPAkPHkEUcqmfR/Y9zsTW+ccn0LB2JBPQJxbTRFjvIo59Fr
         T01uRHJ8fTsEJN5IjifF0HOa8MaWSGl/jG2iGSFJALpfYH8jhaLiod/XRI4TEAp4t525
         mgWBittxW6u6FJlujIl6oUGo6swBDO+yW7knySnu3Q7YK9DWh178wJRQjzoWHX58ivMW
         JV9/1Rflf1CrQgSS9+gI5vqVrNVZYOeSMmKCxs2Xyo5pGZc2YK3fwwvTk8PbFVRLD7Xk
         AGNQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWA+ij4J0OOgmkuitAjrPqv2QNB41sRcn5WXCORkapB3p/XNFNB
	CelClLxlXE1uLwTaLHqzAvA=
X-Google-Smtp-Source: APXvYqxaxf5pQp+shuOS/VMLUd2EY6f4OXGcEuiEY85LEJIeOqjZeVioqTfG+JUwyeIrAUSNZScy9g==
X-Received: by 2002:a92:c990:: with SMTP id y16mr2728659iln.105.1579345473311;
        Sat, 18 Jan 2020 03:04:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a6b:7205:: with SMTP id n5ls4476410ioc.3.gmail; Sat, 18 Jan
 2020 03:04:32 -0800 (PST)
X-Received: by 2002:a6b:3f54:: with SMTP id m81mr7367368ioa.190.1579345472806;
        Sat, 18 Jan 2020 03:04:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1579345472; cv=none;
        d=google.com; s=arc-20160816;
        b=mrSf7wvfhUjalUsppoH8Vk0ufIqx+VpiGcy/ucJZBmhhYDyJpzinVuTBpRAUqpb+mX
         mWmXKcVZLFQKS5SxUPwtGqw9+wHDBP/ZO1wgT5NhjE9s43DIpFZ0I6by9/lSPGxwK7Jm
         d9UBUpq7SbXbg98QRB+UwqnXkuKMp4TUrDUQFF0wuLGpBH7CsXnmQohTBA4P6SihoGIl
         9YqgwjKD2o5Mj6hqJzCK7Sqb6hM/9oU3FFHTI1EqgPwy00lT6QLP4UBlCiFhLWBf0lSQ
         3uSsSPEmhbr6N5LeBNbPg33FBwAj2chbedb26AvhoS8YxyuVIlgNuiuTrEoB/UrhQMUM
         oBiQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:in-reply-to:cc:references:message-id:date:subject:mime-version
         :from:content-transfer-encoding:dkim-signature;
        bh=E4iQ7ZDNrYmzMAHeHyv3uP9yYvMQ0RsRxXZm7yOz4Cw=;
        b=diwEPOY5IyPZ7+9MAWVCxiqfTITX9C0L86Z+p3JE5+b1/FYzfE/Nqc/ut7hd1enU1b
         8+MDCB1BPyB+nf2aIQjf6B5DVOqfmTCTVPGPmZs5j9JvyR3ijULwIP4Ahy1HqFWmmxOL
         WiQfBY4SAG58nhGYJPgNGLIm5TtmeHSkWUBY5Mn+7MpizEANTnfVg13es+pUR4TTdzH7
         +QygGnjapYJTRZLZ/q12yXL6HjfoxphlzSZEEWXokHjtKyoq3oDPtJ3zVD4AikYBVUAn
         7d2ZGUG2Q8I0tkPUhq2TslWB84aAKpa8MM+3ZKaC4157qzezgaFLTSIiqzvmO9jvgs5Q
         gV5A==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@lca.pw header.s=google header.b=d6JswzAO;
       spf=pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::836 as permitted sender) smtp.mailfrom=cai@lca.pw
Received: from mail-qt1-x836.google.com (mail-qt1-x836.google.com. [2607:f8b0:4864:20::836])
        by gmr-mx.google.com with ESMTPS id h13si1135329ioe.5.2020.01.18.03.04.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 03:04:32 -0800 (PST)
Received-SPF: pass (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::836 as permitted sender) client-ip=2607:f8b0:4864:20::836;
Received: by mail-qt1-x836.google.com with SMTP id c24so13091138qtp.5
        for <kasan-dev@googlegroups.com>; Sat, 18 Jan 2020 03:04:32 -0800 (PST)
X-Received: by 2002:ac8:7a70:: with SMTP id w16mr11517454qtt.154.1579345471965;
        Sat, 18 Jan 2020 03:04:31 -0800 (PST)
Received: from [192.168.1.183] (pool-71-184-117-43.bstnma.fios.verizon.net. [71.184.117.43])
        by smtp.gmail.com with ESMTPSA id s1sm12892978qkm.84.2020.01.18.03.04.31
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Sat, 18 Jan 2020 03:04:31 -0800 (PST)
Content-Type: text/plain; charset="UTF-8"
From: Qian Cai <cai@lca.pw>
Mime-Version: 1.0 (1.0)
Subject: Re: [PATCH -next] x86/efi_64: fix a user-memory-access in runtime
Date: Sat, 18 Jan 2020 06:04:30 -0500
Message-Id: <934E6F23-96FE-4C59-9387-9ABA2959DBBB@lca.pw>
References: <CAKv+Gu8WBSsG2e8bVpARcwNBrGtMLzUA+bbikHymrZsNQE6wvw@mail.gmail.com>
Cc: Ard Biesheuvel <ardb@kernel.org>, Ingo Molnar <mingo@redhat.com>,
 kasan-dev <kasan-dev@googlegroups.com>,
 linux-efi <linux-efi@vger.kernel.org>,
 Linux Kernel Mailing List <linux-kernel@vger.kernel.org>
In-Reply-To: <CAKv+Gu8WBSsG2e8bVpARcwNBrGtMLzUA+bbikHymrZsNQE6wvw@mail.gmail.com>
To: Ard Biesheuvel <ard.biesheuvel@linaro.org>
X-Mailer: iPhone Mail (17C54)
X-Original-Sender: cai@lca.pw
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@lca.pw header.s=google header.b=d6JswzAO;       spf=pass
 (google.com: domain of cai@lca.pw designates 2607:f8b0:4864:20::836 as
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



> On Jan 18, 2020, at 3:00 AM, Ard Biesheuvel <ard.biesheuvel@linaro.org> wrote:
> 
> Can't we just use READ_ONCE_NOCHECK() instead?

My understanding is that KASAN actually want to make sure there is a no dereference of user memory because it has security implications. Does that make no sense here?

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/934E6F23-96FE-4C59-9387-9ABA2959DBBB%40lca.pw.
