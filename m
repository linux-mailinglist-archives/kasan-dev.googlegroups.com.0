Return-Path: <kasan-dev+bncBC24VNFHTMIBBWELZL6QKGQEXRXEERA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x437.google.com (mail-pf1-x437.google.com [IPv6:2607:f8b0:4864:20::437])
	by mail.lfdr.de (Postfix) with ESMTPS id 882CB2B4557
	for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 14:59:53 +0100 (CET)
Received: by mail-pf1-x437.google.com with SMTP id a24sf12200920pfo.3
        for <lists+kasan-dev@lfdr.de>; Mon, 16 Nov 2020 05:59:53 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1605535192; cv=pass;
        d=google.com; s=arc-20160816;
        b=aX690dUlipOqtMuABJ1SFmBvytnf7uahplC6qCxpmr0ECnTgUqOLxG5/TiGakDIc2Z
         RKlolDjhFSqO+oeVg5EjfvQCBT+nVtT7ChEOEFjn21Q0zdcr4BkjqAAvpQZrAyEQ2rGU
         QcAcYKA4VqI/m1u4SjLh7WCAZ6Uu6kwnLFF68q59JwIpL38TFt3a4k9ruK0s9hxLmBTT
         Fgpk4fuKyFBUNDapFYfj7PEVsSQ/Wze0AGI1FDeHGcOYXAYxzZpXuoWs/q5rew7QQ4VO
         i6w7cOTWgcTecyClNJn5Tm8IJmjlZDK1uTlGP+w5/V+VIoZoKQEERK8bZRa8UD8EXS9d
         FESg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=4cwZIO9UdgpaBKipsuwDqJjL0CfifMWNUoHPVh1tRzg=;
        b=M1/pSwNwsrh8bFLvjP02t4qP66erl5Apy0bCSNIwmuvqtiMq5+tNlRmCqi25OOEaQS
         45/LZGiaN+i4/Kc/asjjaZmfDLfbzmBF0NDvGKysx50nID1MmAoQIb47SmEzF6fA7om7
         bCwG2uMrppQLcwCtti1WlsMVBpbZ1p74FvWelZEBuc3/Q3xH5qheNKZkwE6p6618Lw6L
         09enyVXFNhjMDKs89NJCq781jISAsOAK4b0nJwBrmr7wG8ahafzBSV+GWH4Ki1wNnokL
         tGwkA79kpNQgeMS92KOZgM8YLgNCKCRenOoSudXBwlggfTC07wok3FBvjrn9jgXa2EzS
         KQOg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=4cwZIO9UdgpaBKipsuwDqJjL0CfifMWNUoHPVh1tRzg=;
        b=bXEG5S5HsOvO+qaxLTZZiJfB+XLRJ8pHfcsFc6XzuLfVXruCksxM/HM0pyLHaF+YN8
         ylwEw9asL333tH+cdGt9zEg+W7L+Mj4l+Pb58T6JVN09eoxjByTVBxcEtcJwI36+2Wi7
         pW2qBQcyGoo5LeiRGYPbzx9gmM/zdy+deF2PPFk+3kVjBHSV8X7YoeTpwoW0rHUPc+KT
         MqWDCvUtPmXRUWQ/F3ZpdB91GBECcT/0Rmy+ALiWglWnkcDbQ8TuzCQoAqGvJtInEMyz
         EHW07nXKcJFVavfKpfaFO8LmvJUPFAJuf49po4rA1qsjmFnUdDTl5m4WZMfl7B9oRT2A
         lrSA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=4cwZIO9UdgpaBKipsuwDqJjL0CfifMWNUoHPVh1tRzg=;
        b=UoCgm4uhtxIxyoOHHc7kFDHH0GZdMqk8QGpmHFMT27hV+JloV+uqG4x71NMgCtSxul
         c2ZNFetQikHdR+YKNknjPQ43rpvxSjQ7/LO82ATsiHQ28iOIgoBw1lMpzUkehbt0dDXb
         3gpffYCXXTrb1ITU5whhvegMKPp739jiAo6l2AkjPd4tNfIBIENQeccJeq29599aMqEy
         2TbQBB9dop5bX447NcDtCMdsAL5M/kKdojQC9TFT8xG4vYMOMZdF6ucgUJFdnzTWIDSO
         v4ufNZlBKP6TxSAD+fD7TMgwlLf+R77SKan0XL1+KIbZwxGwYjzRWTX5+P7PFXE8Zode
         Qwyg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531/I04cVDT+L5HVamhNroL/Gup6+C9ULtrShj2MGFx+OOkR7Nrk
	AO9EufC4WzuAOXFbVghpJ/U=
X-Google-Smtp-Source: ABdhPJyMcpmjRvdL3ZJtkK3TputvYkxU+rhS7xDvyIFHHiVezvyPTfFjonauy54DH/D/I1iWA+DBJw==
X-Received: by 2002:a65:6847:: with SMTP id q7mr13347271pgt.42.1605535192169;
        Mon, 16 Nov 2020 05:59:52 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a17:90a:be18:: with SMTP id a24ls4905203pjs.3.canary-gmail;
 Mon, 16 Nov 2020 05:59:51 -0800 (PST)
X-Received: by 2002:a17:902:a9c7:b029:d6:da66:253c with SMTP id b7-20020a170902a9c7b02900d6da66253cmr12953595plr.19.1605535191675;
        Mon, 16 Nov 2020 05:59:51 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1605535191; cv=none;
        d=google.com; s=arc-20160816;
        b=0Ejog1AgYEIobLqyTfcYkT7UGGX0LS2aQGlundTt8Y3zP2ZsbywvN615oRXwOYtnWz
         X9DcN4N2I8SwysLDtrlbJg6JiDBrtW2+eCUciUhPDaqIL/2Yu4Bl4Lz7dfH8QaLjSyDM
         GVe3yLXPBu6nFY0FVyT1qygc7ux5KH94zfuAnj4c2KFUdp8UNiedTZjtA4kU8j2Uk765
         tjf8tkzPPa9MupDqEjkBjHSetxabyOhcA89/SOZzi2wrDaNYG4Yj+7QNIhNNIPypmEDs
         yWORG1iW0Y6LsGFyspYSPwPJpSfHg2jOAGfY5uG2ti8K3XG6drCkhjR6OcBdxOUbK9sr
         Sc6g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from;
        bh=aEl1TZaGR4X20qL4GbP0rzXbEwypjYE4kNlWSRU1JOk=;
        b=xmHoVgvZEZmKZ4YgC0VEfSetZLoIigGMwhtcMRBIcxtLLDtry3B63Opuy8CVltoAAP
         F6iNc3bV9OHzs5vUiiB9lQToHQBa16UMNLOW2F169opUR2gZQokUkxJjdmgpn3Z2NWKk
         VpTD6h+ESMIxLKvVL7ft2VSVLLi6o+yWytXoflH6W9cn2zBkZ9L/N1RdcNCSHp+muLMk
         Ly/Lt6g5g1P13SKMA7loBsYc2to3AUWuPEDn/R1ZxXoQ7EWQezAXPbpkv7i0BQenYzua
         qozahK6mCHsyVsm/ZkAtCbq2gjBkTyXcQyL/VXzBMPOp2OU3XwvUn81Re3I3SXS2NPlP
         kkAA==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id o24si1182012pjt.3.2020.11.16.05.59.51
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 16 Nov 2020 05:59:51 -0800 (PST)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 210221] KASAN: turn CONFIG_KASAN_STACK into bool
Date: Mon, 16 Nov 2020 13:59:51 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: dvyukov@google.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: cc
Message-ID: <bug-210221-199747-t0L66gCR9R@https.bugzilla.kernel.org/>
In-Reply-To: <bug-210221-199747@https.bugzilla.kernel.org/>
References: <bug-210221-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=210221

Dmitry Vyukov (dvyukov@google.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
                 CC|                            |dvyukov@google.com

--- Comment #1 from Dmitry Vyukov (dvyukov@google.com) ---
FWIW we could also have just 1 config instead of 2 as well
(CONFIG_KASAN_STACK/CONFIG_KASAN_STACK_ENABLE).
For gcc we could do no prompt and default value y, and for clang --
prompt and default value n. I think it should do what we need.

-- 
You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-210221-199747-t0L66gCR9R%40https.bugzilla.kernel.org/.
