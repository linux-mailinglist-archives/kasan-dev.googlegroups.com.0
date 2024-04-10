Return-Path: <kasan-dev+bncBAABBZFI3GYAMGQERBYFI5A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83a.google.com (mail-qt1-x83a.google.com [IPv6:2607:f8b0:4864:20::83a])
	by mail.lfdr.de (Postfix) with ESMTPS id B854E89EE17
	for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 10:57:09 +0200 (CEST)
Received: by mail-qt1-x83a.google.com with SMTP id d75a77b69052e-4347ca57eddsf417341cf.1
        for <lists+kasan-dev@lfdr.de>; Wed, 10 Apr 2024 01:57:09 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1712739428; cv=pass;
        d=google.com; s=arc-20160816;
        b=A/Uil6fY2CYzOwWGvJjqSdJhlykDmIx7wHQVmnmJgs2Mi8BEWhFEp8wOJB/OoEjDly
         cYOTA4JgGwdLYQTGfbiihxv7RMiTgT7/3yqUJMB/1qi79/v6b6/HUxDxT04fO7rfJ/vi
         eaHVmo58ZMlofhhjc7rIlwhQXHsIHLrbgr/RDU+i91NbFbtR720Op/b/k6nFOIxiRVYk
         aHbDFCjIAcAzg5bOr24IepvFTyR/L3OfE19KRSfx9i2fQH3oDXfmnMIB5oamlQFvbQLM
         ulBPBsxFTD+RCUUC3rMGmuugAjkbnAjXzMfM19S99XEqngtT57uEk0nAaPvciwVnmWoL
         DKIg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=JvI0OPgvt6xluVHb+tR5PIXb8IL35mEdSPbFzuLSy0M=;
        fh=Iud751znlPb86sJbgMOW1kLGXz1mQxpKoZRigTo/d6s=;
        b=arf9pT6BIqLrOVRPK9QEUyP6BUuOpi0magxay4qZFJJpcSzGfDWG3gABz6/2acYuLe
         nr8FEsJ85mBt9a10pnRzajNpGqMSz7M+KbpZdJDxJuiusFiRQfGBNnhkm7Z33f2oQaM2
         9vLrovROBd/Q4xCjQCzR+9zimImLlF7dpDMJpEnjmpvwquPo9aOYTQMQtL8Bs71XY+u1
         Vu1ywsd801jSGJfm4PfYCJDYmSdgUVUHHu1e4Fw2sfMAnmpfg5g4agaCDSePAH7w4aBf
         zxsNnbm/ti1C5VrrS3XSWxEO9gluYb0JoTrxTXoJq+hfzW82l70T9VbWrL2temRC5Wjl
         HXJw==;
        darn=lfdr.de
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NbQjNwp2;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1712739428; x=1713344228; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=JvI0OPgvt6xluVHb+tR5PIXb8IL35mEdSPbFzuLSy0M=;
        b=QrU4U1fp0iq68aN3/GpVLfb23Ks73aBIlt+phc0rHYY8kaeWUaEWhChgXt85khb3wT
         adHJ8GalBXkWKj0DxOVfLmuwEYOvrwb5FFVWYa43tVMK+HCB28eBm3tZHMLpnzLAf+so
         KpwjGdmPqrnxptbAYpegalEs4E1DOAMeh/POcl4IRFedHdREDW7vXk0nEhBPa0d48CNm
         BBp/t9L2cqBX0Nkkl83MKA7HeJR7gpJDNbjtmpSeHhIjvedWsveu9v9CVQF4gP/qr9f2
         SmAo2Rm14n6/y3Z8eq893037CQ6jyjm0zU++hR1PNf8f9JxDSQt25P3Se9XR5IttpTkT
         D+Wg==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1712739428; x=1713344228;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=JvI0OPgvt6xluVHb+tR5PIXb8IL35mEdSPbFzuLSy0M=;
        b=J0+VR7qEsh9hi2DApCM6df8S3E/ODqM1xBQ2idWTc7yHm5ntwjq7vsS80vDb0Y9JnM
         X4n9R6q3kh3SkOC+0zMpjcndWz8G5Xk+x31lzT89wY8MdMDCpw5fV9/4Kj/k3ZV1c5AJ
         EG4oLpA8xxlOP65UoFiiuSpe5kWCRgYR/5r5iBH1ANxgO4EoLbNM1ICnkTmBbAt/RjeW
         lBU7AtYxUMWmyvR/z1QmxvSd/MKqXQBY/WtIjTXAGWGNCPx3BReUoNdzhrnqNVS41Rep
         2jmzKbfr3aDQQfNzNSaKi21veeINb9qcXdukWUSQBPbIBJoXk0wW5c1nE2uIrv0cEiy5
         l7qQ==
Sender: kasan-dev@googlegroups.com
X-Forwarded-Encrypted: i=2; AJvYcCVjaJZqb+J7+fW6JIJSDwX7msOP5dDn9EiASz6k71VoXGYcTX/TZDLeKqvbeZ/5Ca1XBwsPaUUX1QWLPDRsT8CMrQkB4BUT3Q==
X-Gm-Message-State: AOJu0YzpAoORau+P6L+xHyBkL8NInKwUSAdDMR6JOBPEtYLC4fEcpWuY
	HsV89zrn5wAgaB6Qd7bnPQtUm6weJQFu6mxDNfd7P47YkwIdKyfA
X-Google-Smtp-Source: AGHT+IFTSh7QjyA91CY5o11ogK9YkCLONagaOQl1Gahe1jCUsKiFm/dgME741rdS3O/TlsD1dqpQVw==
X-Received: by 2002:a05:622a:428d:b0:434:96f6:cb76 with SMTP id cr13-20020a05622a428d00b0043496f6cb76mr196216qtb.22.1712739428487;
        Wed, 10 Apr 2024 01:57:08 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:ad4:5bc1:0:b0:690:c124:c187 with SMTP id t1-20020ad45bc1000000b00690c124c187ls1802156qvt.1.-pod-prod-02-us;
 Wed, 10 Apr 2024 01:57:08 -0700 (PDT)
X-Received: by 2002:a05:6102:950:b0:47a:2cd2:c24d with SMTP id a16-20020a056102095000b0047a2cd2c24dmr59635vsi.11.1712739427534;
        Wed, 10 Apr 2024 01:57:07 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1712739427; cv=none;
        d=google.com; s=arc-20160816;
        b=Q7Q1N8XbEn0gDjFlvBHCzwMWmxsB/CvJzlY6l6P7UmAwJjBthgSP4Bc56nzFG0P/Ou
         yNfQsUbgufvHMuy/WqwQv5/ZIql6nxzwo9MpLMWB2CYwZsKHjI2GBZOvVHiCiR6oa2Q4
         V0eheiTWfWHfBmpKr5l1COf+PEGAVKn+xTXitDO0qjHWtnvlq32PoIrpY0mpiP3v0GYl
         kq3o7lUK9CvIEgGlb5Te6f9tR7oaUYJI4HbrxLgzz9OxlBgKHroL/S85TRlei3OyshkD
         p2FyPLlkY1+pPucxfvsevrTSVuz9IrJXMWM0FGsLc+u+nwj2vlwZchmpixzSX37TrN1h
         SSbQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=zWWr8iIMd/B0HxZyoYa0T6DH6/0QF1tpwSyaHNkfSmg=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=O4EMDZdV/tJNyrMtLiWufqAFHNp5N3DIOmIoiLeHOGmjCO129pi0fXeqoT7XuyWtJB
         lP+m7hCANdNAuD8AYRtNYfHvSwuVtuUSpdYti3hCtFgRleJc5tJbPO5BmEKeDMIzQzPO
         yABvMjWdGmrmMwz1ldB6p5586VtZsU4maoYk90MFfbd1gLJDORqUMmNQEldWCtiiBMBe
         JZtNNysqjMLp+L2+Tk89rKDZV73LioYJLuLaJXDBbcKpq5LVCy5jUmx4bdvFpvkWMxsK
         MbpLL/6eiX42NjTV8Tsfhg4Ogmn7NbbJ5D947+uJVyDoklmcdUfQ2wOPMkuQHU8kbvsD
         ZvSg==;
        dara=google.com
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=NbQjNwp2;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id cy10-20020a05621418ca00b0069917cb5fddsi783574qvb.5.2024.04.10.01.57.07
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 10 Apr 2024 01:57:07 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id C9CDCCE26AF
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 08:57:04 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id 14A80C433C7
	for <kasan-dev@googlegroups.com>; Wed, 10 Apr 2024 08:57:04 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id 0E0A2C53BD3; Wed, 10 Apr 2024 08:57:04 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 217049] KASAN: unify kasan_arch_is_ready with kasan_enabled
Date: Wed, 10 Apr 2024 08:57:03 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: NEW
X-Bugzilla-Resolution: 
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-217049-199747-UvQg15vWL4@https.bugzilla.kernel.org/>
In-Reply-To: <bug-217049-199747@https.bugzilla.kernel.org/>
References: <bug-217049-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=NbQjNwp2;       spf=pass
 (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as
 permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=kernel.org
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

https://bugzilla.kernel.org/show_bug.cgi?id=217049

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
See [1] for a related discussion.

[1]
https://lore.kernel.org/linux-mm/CA+fCnZf7JqTH46C7oG2Wk9NnLU7hgiVDEK0EA8RAtyr-KgkHdg@mail.gmail.com/

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-217049-199747-UvQg15vWL4%40https.bugzilla.kernel.org/.
