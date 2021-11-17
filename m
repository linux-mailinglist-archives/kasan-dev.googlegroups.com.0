Return-Path: <kasan-dev+bncBC24VNFHTMIBBBM52SGAMGQEDL5SF3A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc39.google.com (mail-oo1-xc39.google.com [IPv6:2607:f8b0:4864:20::c39])
	by mail.lfdr.de (Postfix) with ESMTPS id 0DFBF454851
	for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 15:15:35 +0100 (CET)
Received: by mail-oo1-xc39.google.com with SMTP id q36-20020a4a88e7000000b002c2848c4755sf1800426ooh.10
        for <lists+kasan-dev@lfdr.de>; Wed, 17 Nov 2021 06:15:34 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1637158533; cv=pass;
        d=google.com; s=arc-20160816;
        b=FKYOrVO2QJ4c1yD+gZQH1PYlTmqI2mEsry12DUgM7sa3+J7jwvXqGz3XjQulzc6f7E
         GM+eiuFj0b1v06Bf5fF8SucdDF6Hd7KPnFPJUFHLuPi7RJP1I4jluwWiY+ZEiBZz4Asr
         qfvz/QZWn+o8kuYZVQaWgJfbUW7+OtsY2ll1gvnjaSD2/rCtM7LUrMVhMTzs5pZtMzZ+
         +dmlYfzv2ydemCXY+EoptYVJczMcSQk+VYRSxtTtyOdQHqbMNilIDXkIyIlplrB3KCw4
         m+o9WhFl1uqg+XNPp557TwRsvki9VGd8b1my7bIg0BOMLt6f19TuqOejCf0aaBuVAmWE
         y3UA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=O3jJ7QxHz/fQDcwkA5QfnbjKrNq2meGkfnuSIp/xOAU=;
        b=gcUMtIEL8NmybjRHokAMwwd9uISJY7nqXEDm/9ha5grc05AU92If/i3mqARkMZMIoZ
         qm8+FMVGmRaL38daabQU7EZ2NCfmPKAaycEqA9jw1iuvA2CVThZ+GMarionoHVYPeGyT
         d2pj5sstnjRgBg+gmSGPdTFpaga5x+IrHtIH5YAIokjKUdzMxAtNhOt9mIpI3wAJal5l
         yV5daC6vtmBMcq9g2XJ8lZ+TM640rj1oKQcUJXfeoHNoYKGsIHVtG5ifOOJR4FhiYte0
         ET5HpLuO3hIALgcgTP2oRpf+qf8iZHcGI3BgAJ3VCAzpsiTmnhLqyY/Yykr8mx/JBHy4
         hOGg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pU0p+rfv;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=O3jJ7QxHz/fQDcwkA5QfnbjKrNq2meGkfnuSIp/xOAU=;
        b=kdmVR/gxSkHdNMipyAiI8Mb36dfHdfqL4brubEB64ufu79Ej5d48KNNrDV+v5ACV9v
         bnq7CLSQJi31J1fTXEntmPqwN5K4DXoFYP/RqSl6BNFzgFGmgfsy7xHyedrN7aFqwWh+
         BLT5M8ogxye9E0C/WNCvg+0LvEud4VNNXjxv5SQ51jscfDV7TL+1IpE44Dw/e1Zc48Zx
         exR/kAAffeuq9r0k9EbUqIS27ycc53QstkXqyeBxWHIjc8d2sktgal8VpvPLjNctseRB
         dg3TFiJYbibfeHKFI2fsshS7wQtGOURYAORB+ZH/h8nGT8yVypsf9CHSDPn85LwpKPps
         eblg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=O3jJ7QxHz/fQDcwkA5QfnbjKrNq2meGkfnuSIp/xOAU=;
        b=1d+eS6E55RlGjtm1mYKmDdWCxot7F3DhXdGk8qK6I19WOLyXaE9XwetflCfV+wWYPp
         2FdFaQhTmUejht2WtCZrb3M+1M5msCofBK0gE0fs8lgd0tCWacUDYE4dPnQCYinOMNif
         AFNil2ISxlbRLnKYwN4tm7ZcC/T80W2eUxzcPpbrn5Y6pgknrLPJcFi0NFSIJ9/951RO
         2AXKwb2dgoLz1Y5Yu9XO95resTeMq6GFu51TucMnNtxzMU9t3UeSjUMOQsZT5/rV2se6
         ZS7KqFy6qtm0rV3za/d2LlUkD8QWFo2+srBODxYtjtjnH1p8XbWPj62a5DJCX+jUFIkk
         6JOg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531YC93FIUbL2UeHNORApzggDnMA9ibRNiLSDjfUBRnwlZF1YN00
	yrSn5gfoLFDbyK7sIGNN/fg=
X-Google-Smtp-Source: ABdhPJxi10j+DugpjDalgtxBdOzl5jI733ctbbB1WNLbDoZu1tAn8CYtPcu0BTzHyOb+0REUI0DgQg==
X-Received: by 2002:a9d:12a6:: with SMTP id g35mr13144377otg.61.1637158533402;
        Wed, 17 Nov 2021 06:15:33 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6830:2b22:: with SMTP id l34ls7409283otv.1.gmail; Wed,
 17 Nov 2021 06:15:32 -0800 (PST)
X-Received: by 2002:a9d:6216:: with SMTP id g22mr14450551otj.46.1637158532356;
        Wed, 17 Nov 2021 06:15:32 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1637158532; cv=none;
        d=google.com; s=arc-20160816;
        b=jrHKjqm/+hscrRqr/BngbF6mi2RFv5z99dZy/9TxSZoseTV7SxAN+vrAHTcmx+OYaF
         Nyw+XfeR8QT/RBsz2eFc7BDH96FHO0PBUi4xGDPfX6ZjAuf4HZeItDWWzyFOQ0OzdKEO
         ZniNF9h+LNnZSbGp9Fcsa6wTgGzo9Xdjr7I5jadsmyWE9QgLcFI2QHT6LbWeWyg3X72h
         pj2mwud/3i651qKnHZ+clLq1JkvbjaUQ5jZ/tFpnXrfqWX+izTdXwI8hPMXdJvTRuz3J
         iNXdlGwypdJA6Tvv14HtSncg9letelYhJBYeSkHwKSVwIO6/EmvXYdTZFjj+xrFqIAe8
         S/6Q==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=DYFRMQLmDQTuSA03jwVRHUPpI4QNMkmgB2NXm/QmiUA=;
        b=YUG/O8p3iqHIw6m/D7Sy80PqS6X4UZNff9oLMujMS2IvCLNVGT+dp0VL3UDbeuGMJl
         8uZqy4Bzs/aomJuxr00b0e1T/zoz2ByDPfD/19Yrhd8lbrewRtbg0cPaXiOezW7Ahjj+
         gVc7dJjg8E50SnE59s/swr0NnhIsuH7S+FBJBWsP6R/F555F9nLXq3iODdFyxjX0OVqo
         4FXHwTQadghKbUqjIeTTq2sXLzN1dYlmAd3m/168T5Le6VY3HPfcKiaJbfzuaAnQOaD3
         JdNDlJowiINuJSpxLfwJrUmypW1s9uu4tf4Xv7lQaxyv661Lg7vVwfB5ibo6RO80O8+y
         ovdg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=pU0p+rfv;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id w29si1600409oth.3.2021.11.17.06.15.32
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Wed, 17 Nov 2021 06:15:32 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id 8A1F461C12
	for <kasan-dev@googlegroups.com>; Wed, 17 Nov 2021 14:15:31 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id 81D7960FC0; Wed, 17 Nov 2021 14:15:31 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 215051] KASAN (generic): gcc does not reliably detect globals
 left-out-of-bounds accesses
Date: Wed, 17 Nov 2021 14:15:31 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: enhancement
X-Bugzilla-Who: melver@kernel.org
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-215051-199747-pMcozVSZfR@https.bugzilla.kernel.org/>
In-Reply-To: <bug-215051-199747@https.bugzilla.kernel.org/>
References: <bug-215051-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=pU0p+rfv;       spf=pass
 (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates
 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
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

https://bugzilla.kernel.org/show_bug.cgi?id=215051

--- Comment #1 from Marco Elver (melver@kernel.org) ---
From the patch adding the test: "... The main difference between GCC's globals
redzoning and Clang's is that GCC relies on using increased alignment to
producing padding, where Clang's redzoning implementation actually adds real
data after the global and doesn't rely on alignment to produce padding. I
believe this
is the main reason why GCC can't reliably catch globals out-of-bounds in
this case."

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-215051-199747-pMcozVSZfR%40https.bugzilla.kernel.org/.
