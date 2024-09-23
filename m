Return-Path: <kasan-dev+bncBAABBVO4YS3QMGQEAL7QC5I@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd40.google.com (mail-io1-xd40.google.com [IPv6:2607:f8b0:4864:20::d40])
	by mail.lfdr.de (Postfix) with ESMTPS id 0C2D797E805
	for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 11:01:11 +0200 (CEST)
Received: by mail-io1-xd40.google.com with SMTP id ca18e2360f4ac-82cda2c8997sf558657539f.0
        for <lists+kasan-dev@lfdr.de>; Mon, 23 Sep 2024 02:01:10 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1727082069; cv=pass;
        d=google.com; s=arc-20240605;
        b=XELU6WsDxcyo5BOAVbzRvOKCBr7QQ2Bm5ylmiOvs34Br+vmfpBGwslumscKSVjXLyA
         OoWQzFrc++/lp8gKEECQhPwzS0jPq/E3CQgio3Gg6kYePPG1jgGvsZuxHd6T0SjbiKu7
         uTIMaKz4wX+Zxa31gwaGye2W8WDUXlxwkbCWacNGcmD57Ius/NBCH3OA79/UzcQ++CEr
         pTty9SSNYX0V9n72Rw002x5o8xb+3IvTPGRjpf2A/2fYX7ebGRisxlE7WTo5d/7ZfjC8
         QacfTox7m9DgttusiRRXwouPqxlG0cl8DSJGMCaGB289Df/2/dVbV/dFBjabTNZpe7Mw
         o6UQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:dkim-signature;
        bh=Aj1Du37UoSE6MhS4I+q8CmUfxLLCHvNjm9ZIKlDMuII=;
        fh=1h4RAG8RgXmyfWzPtJNVh+P+ABya8TMZE+rKB1JiXTs=;
        b=H6MYXtWlQazPeQUgJY3tG7PqEygry0Aati+QxsanClwrginas8qy8Q8fUki7jYX/qk
         YY8DZ04vUKlSKd7hcEoPMMyWa9Zl0JxRJumVVtLjLNDyuI9y0jtl/yAO5uMaXKiVcTDc
         5WPXM2KWzkwY0ZSCVcTSWxuSUu3pWAobnDdw6+rtePLSgyBgivzh1FYWySR3oONPXoyC
         3uWBKRYAQbMBrpyo99ylJ5o979MeV0DEoqO9/QLfTMQFMZd7KxEKXyq6HqyWobfvS+FW
         2kWyi1VoDqdZTlSQhz1CpSprhY4kkB/4yPXK5dNm1GieApji2hNU1Re/F+vwnuJZunes
         NFqw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W11frmkN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1727082069; x=1727686869; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:from:to:cc:subject:date:message-id:reply-to;
        bh=Aj1Du37UoSE6MhS4I+q8CmUfxLLCHvNjm9ZIKlDMuII=;
        b=dO61s6KF6SJf5omAI65P2Pg1eCSQRn0wVahtKuvoTJFaTNYCEzRRQe53XrIhiOr+Wb
         dq0YSJ5/41DLehtEu34LvHmc2n4OvuBiz2UKeNbxZNW6i/t2q2i9JbV8qXOa4+0Ju/LK
         JraYLB5PsRrpRNv1XyB3gOTWinSs5knNAANXpLdjWhLOq58JBjMpvZftK54es/5JJPtn
         8Ys+iUA7qGydB7oO0d9qGdo5e0hkLXm4mcRZ9kw+E/n4L2k7QKNkgwv2NZashxVifgaP
         b5F7N5vR4znsNWaumQISzqHVdViwx3rVXRx1W/2O27heJAFTuNgSfYAcrmo0kXDnUaY7
         VtAQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1727082069; x=1727686869;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence:reply-to
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:from:to:cc:subject:date
         :message-id:reply-to;
        bh=Aj1Du37UoSE6MhS4I+q8CmUfxLLCHvNjm9ZIKlDMuII=;
        b=UBWecl3QXJH2wa6qW1LuJrNEVJGJNqB79fT0DZz4cqT6La5GR/7diSyIG3oQKh6aLf
         OoDPSTw9bNPiVbHidbbO/WxCiNxz2eKPh/RFh/RNTAi6FwtDjiYHfxMlGscIY0w+p84+
         zxQEkCAZwhPkSyFCQ8IEcbvZMtyT+uhNzjSdSY9gVL8eN32+wsUbvuZj7co1ztwBIgnc
         sySBURFYn4JoIlerfluWh8kTZG+54IjUZPxKX8dZY2FLtNz4M4/OsXY4JMrUgBj3/HcF
         tjeMCXeCfBt387xg8CiwVCQEVzsJi3x4KpED3BiZMo46hL//X+sMUr2SZtr+OV9Qxplv
         EbZQ==
X-Forwarded-Encrypted: i=2; AJvYcCWtOaM8kYQcsidqh6AkZl88Bsyfj2uz0uE21OGuEKuL1aiQ+jmI6rU+xJUG+bbl38nNIG5oEg==@lfdr.de
X-Gm-Message-State: AOJu0Yz0/uwF01njmpeMcu80M6TEOvLmAqAUJ9umlGET0VF6mkdRIL5G
	kJtGIO44qJzmgpGK1qk+LKsyGMMPpfw0WVMS9er7+/Z3Zv6WiFR7
X-Google-Smtp-Source: AGHT+IF3FhU3tVHIt7NC+xw7vpOrO3xK/ZnSohmwaVNYEpnx8OnejNQTjMvjiJQaNpoEvGkXjP4StQ==
X-Received: by 2002:a05:6e02:1d8f:b0:3a0:9d62:3b65 with SMTP id e9e14a558f8ab-3a0c8c8e79bmr97714485ab.3.1727082069367;
        Mon, 23 Sep 2024 02:01:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6e02:156d:b0:3a0:beb4:f1e6 with SMTP id
 e9e14a558f8ab-3a0bf14f92bls21123525ab.1.-pod-prod-05-us; Mon, 23 Sep 2024
 02:01:08 -0700 (PDT)
X-Received: by 2002:a05:6e02:1e03:b0:39f:6f8c:45f3 with SMTP id e9e14a558f8ab-3a0c8d25d74mr81661875ab.16.1727082068671;
        Mon, 23 Sep 2024 02:01:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1727082068; cv=none;
        d=google.com; s=arc-20240605;
        b=bhDjyaIejvyW/V9vW6s9rZk7USZ6iNW2SK7B88u1YuTWhDS045eq3VQrN9H9s7Vuf3
         cUC6w0XVM5mGVpCypmuRXrWUrzE/+9Ngeks5t5RXY/NE0NpHN9PNzp3lsw0jAblvg44V
         ziAlQCPRPYjTA4R07CZ6BA1oxM5S79nMjvPES1486gvhUOfP00YpvjsmR0tnGvgSWaCw
         CZbju4drBCIDeNlYEvq6uGIXgXD5vAfBt8tocLtcmWuDOkPBlJGettiKzcrjsbOv1wBI
         uv0mlx4KwEOBsOzCBmU6LOJcpUkfweEr9JlnOa7YgtPVYS65/1Wzk7UG2oauHOZb/F6z
         Epgg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=B6L8xwwAfdS1LpZCjD65ox8sjBo1eyLTD6W+v4wU7rk=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=jvwRk5IcsIKgGoAP4siHohjfCRCFHp2t5HZUlN/oOxZdNwx7vpYeIhuEx3gTl+pEOJ
         4rhBnQaY6xFy3P6rzwLj2Zta+0pn8DLcCbAF/tsI0oqWV/OYzy69QnQJhHTSAUXKg6tq
         xfj5i45EoZgzAOfArBWn4GoyejDxYw9AC1sEY0eNCpeJLd14jlU7NwKtD1Q22uBgDklC
         wQOMj+zkVDd/KZcKY/qkWyljNohkQTfSYplH1VSb3G5DW+AI+hjTvBFE5q99NPBbaefB
         rikSe94G/AEKg/WjGyie4UTzb1d0mwKdNW7idzo6qAq8VCpXg8xIKpGWl95sooT36Fhp
         6lEA==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=W11frmkN;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
Received: from dfw.source.kernel.org (dfw.source.kernel.org. [2604:1380:4641:c500::1])
        by gmr-mx.google.com with ESMTPS id e9e14a558f8ab-3a0cdb0486csi2435875ab.0.2024.09.23.02.01.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Mon, 23 Sep 2024 02:01:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 2604:1380:4641:c500::1 as permitted sender) client-ip=2604:1380:4641:c500::1;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by dfw.source.kernel.org (Postfix) with ESMTP id 6B5355C0C35
	for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2024 09:01:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 03E27C4CED2
	for <kasan-dev@googlegroups.com>; Mon, 23 Sep 2024 09:01:08 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id EE48EC53BC7; Mon, 23 Sep 2024 09:01:07 +0000 (UTC)
From: bugzilla-daemon via kasan-dev <kasan-dev@googlegroups.com>
To: kasan-dev@googlegroups.com
Subject: [Bug 198661] KASAN: add checks to DMA transfers
Date: Mon, 23 Sep 2024 09:01:07 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: dvyukov@google.com
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-198661-199747-hgrHmauTrG@https.bugzilla.kernel.org/>
In-Reply-To: <bug-198661-199747@https.bugzilla.kernel.org/>
References: <bug-198661-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=W11frmkN;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates
 2604:1380:4641:c500::1 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=QUARANTINE sp=QUARANTINE dis=NONE) header.from=kernel.org
X-Original-From: bugzilla-daemon@kernel.org
Reply-To: bugzilla-daemon@kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=198661

--- Comment #4 from Dmitry Vyukov (dvyukov@google.com) ---
Thanks Arnd, this is useful.

I see that dma_sync_single_for_device accepts dma_addr_t and the comment says:

/*
 * A dma_addr_t can hold any valid DMA address, i.e., any address returned
 * by the DMA API.
 *
 * If the DMA API only uses 32-bit addresses, dma_addr_t need only be 32
 * bits wide.  Bus addresses, e.g., PCI BARs, may be wider than 32 bits,
 * but drivers do memory-mapped I/O to ioremapped kernel virtual addresses,
 * so they don't care about the size of the actual bus addresses.
 */
typedef u64 dma_addr_t;

So these are not the actual physical/virtual addresses that the kernel itself
will use for that memory, right? This looks problematic b/c we need to
poison/unpoison the kernel physical/virtual addresses, right?

I see that "sg" versions accept scatterlist and scatterlist has the kernel
address info IIUC (it looks like page_link is struct page* with mangled low
bits, so at least we can infer physical addresses for these):

struct scatterlist {
        unsigned long   page_link;
        unsigned int    offset;
        unsigned int    length;

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-198661-199747-hgrHmauTrG%40https.bugzilla.kernel.org/.
