Return-Path: <kasan-dev+bncBAABBSPGSSVAMGQEI47OFOQ@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oo1-xc3c.google.com (mail-oo1-xc3c.google.com [IPv6:2607:f8b0:4864:20::c3c])
	by mail.lfdr.de (Postfix) with ESMTPS id 2448E7E07C6
	for <lists+kasan-dev@lfdr.de>; Fri,  3 Nov 2023 18:52:11 +0100 (CET)
Received: by mail-oo1-xc3c.google.com with SMTP id 006d021491bc7-581da1346a5sf2886063eaf.3
        for <lists+kasan-dev@lfdr.de>; Fri, 03 Nov 2023 10:52:11 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1699033929; cv=pass;
        d=google.com; s=arc-20160816;
        b=scCYmDDFFD4quGwRrSmvANXrq3zUaP76pT26lnFG1wAR3eKRFtKzxJw6V2oaQ62vEy
         NLT7udd9hHH9PI8MEKovAntLTy/XabT2TU4XvgDqrLXrS/eL+vhH0TSgr7SjC8GyDR+E
         6AlaV3H4zsGkwOjb2ETa0FQeFAWdSTFBzvK3fimBTndUe8ZttjcGqbnTf8nqfrYapbfb
         5sOAYf8cuCdmzNlbU1WbsqFSWLjlDCe+J9dvHlEH/A361ZhxivDgX0i9ggi03+oWX9VT
         LZmTqzy0mBFHGstLCLq+iWYQ574VUu93Ng1+Ua5tOqUb8QSi01GZL0mR/CGpAeL1VDfo
         ydvA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=6q7ACnA3ldYT7UBAJ+LpnLhMcnvRhWZaOBRv+9l+mYs=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=m2OuNpqpOfqOn5F1X/uIk5xa+EQrqDysQe3WaePiQTitGgEYAkCWKAJ9rwvGjivAqW
         8cU8N3Z+VcJnjYXZW+vQWcjRIS/XVzlhaH5U1kp6fiUFkQ6uQfSUT1vXdfX87kaQQq0w
         9N127KkTIGUULt81rNJe92m+x1YOTef8kCIiFNJ5oP5uszfljfaNRuJzP+RbCt6k1IXb
         PArv3nvGyuOS27HIZApA+4KyqD+FNi4urloXrCA8UjBgZXdrVNYZp7vqBETfHEUhPXFQ
         Y6oHFSo3FQCuBi3x97zg1sMJR+EQ7CJSu6vPFsmYSIiISaO1aBZHgnbnnExGNy7dPEcP
         rtPA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Stz4O6je;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20230601; t=1699033929; x=1699638729; darn=lfdr.de;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:x-original-authentication-results
         :x-original-sender:mime-version:auto-submitted:references
         :in-reply-to:message-id:date:subject:to:from:sender:from:to:cc
         :subject:date:message-id:reply-to;
        bh=6q7ACnA3ldYT7UBAJ+LpnLhMcnvRhWZaOBRv+9l+mYs=;
        b=vaH0WRqEukqEGbAU8SGRX6QTXfLFc6ZpT8ltwaMfk9WB5ABqZcHGtprOZUtVP5LaOr
         WhZicaU+x5vN6YADtgTECiRpTRmpkk6mdMNK3jKg9Euupp7isWDAxftuszg8TxaV8+4M
         GI+HgOEEfLP3pnh4rFaBcUvEGWoP/T3ExHFD6U64IXZBPwS3hL2Gggl8TokxSLy4laKn
         xR/DJzzarS0t7YiHg65GGSvdJrD1J1SfXSZ0ACXUusjjtZfahjX3SMXYnzeiTBezZdYV
         QuriSNnT04vnlU5o0q6wROOBQ2pqWoNdkH47xwWYdyhvBxXCtWBLpJxDP8liJYAdd8rv
         DgVw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20230601; t=1699033929; x=1699638729;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :x-spam-checked-in-group:list-id:mailing-list:precedence
         :x-original-authentication-results:x-original-sender:mime-version
         :auto-submitted:references:in-reply-to:message-id:date:subject:to
         :from:x-beenthere:x-gm-message-state:sender:from:to:cc:subject:date
         :message-id:reply-to;
        bh=6q7ACnA3ldYT7UBAJ+LpnLhMcnvRhWZaOBRv+9l+mYs=;
        b=KA9W6D9ZTHwEQyR/msi/huTE8PYQL+555XSuU4clRlr60VgO9G54v+zA6IvSod/yL7
         TmY/WdqYryq+RqV27Q7imIlhdrTdEW1Mz4OEtfhe76xu641ygbkyidFKK246swKiDz6/
         lRoj6C6X383UpixRluSNuQWraXnWOZXJRRLGrkDFmKASvRPSL6uufVr54gXSwTZyy8iX
         2CCZ9B5m/+s1nGac4EL9jy+8zE50s3pWgC3zYPLRLoWqfb8ejKFfpQs+qcKRTzwZaFiJ
         9bNp3Lm+mDUs8bs/CY4i2mcw/ny5EWgSttxmaqT6KJBLLZaBvStJK7ahKanLXT5Dk91V
         vAsA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOJu0YwmAo6l3Af1c3VakuzTTXOrBtIcpFUzY3kalbwO7jqr2M/HXV1k
	PbjTLGieyV7ROqRhDqq+UlI=
X-Google-Smtp-Source: AGHT+IHV7Ynrt/hds5YYFoMGVK+MgGtqzN8eq0p68idBgjKvoEdUQYOyy1m85RILRYb2Gklr7bct8g==
X-Received: by 2002:a4a:ba06:0:b0:582:99ae:ca47 with SMTP id b6-20020a4aba06000000b0058299aeca47mr21520200oop.3.1699033929531;
        Fri, 03 Nov 2023 10:52:09 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a4a:d65a:0:b0:581:d9c2:d789 with SMTP id y26-20020a4ad65a000000b00581d9c2d789ls2811444oos.1.-pod-prod-03-us;
 Fri, 03 Nov 2023 10:52:09 -0700 (PDT)
X-Received: by 2002:a05:6830:43a7:b0:6d3:264e:ba91 with SMTP id s39-20020a05683043a700b006d3264eba91mr5517088otv.36.1699033928936;
        Fri, 03 Nov 2023 10:52:08 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1699033928; cv=none;
        d=google.com; s=arc-20160816;
        b=Ko9BVtiU35c+gB/+oXG6zldU67q5Rolwca67SbSx1Aoqn8rQ3dpfJQwhnlzSzjieOZ
         NST0ir/dYNpTpvP3iUGBGJIKsD0Pbpt8lqTb/J+fP82+2CwNRQwk4jARQjeB4TG+mKwy
         MIJatg3ymIvg36H2MCMuqq95q2zZgbHppWJIxN1f+bAUodwUUKW3hGl8/uaqt7G25ueA
         iEwtTZpjJJvmXmU56DenyBpuHTtB+cu06NTxxFrZJIGAKVhYxh7Tpz1G2h1hCoHYsOC1
         gjS4Y3pxcjIVekzSCmVHNiQzzILh8/5FBO+DrrApl++XoRwOPcL8hTQ+5ub7C7YpbxA/
         /jzQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=F+ySpHgWdy3RuLiOo+FJQetTeurftbnd3ypp4Z5OMrY=;
        fh=uQCsmYQr+KJEcG63Y45gsyDulzJl/B4EdEfpx8XrGGo=;
        b=mWbTysI8s0ulF4VO+8+1mrrILpv3k6kM7xIFq35R2wxuGwTYkAvtQhQ7qxB5NL6ejA
         JyVIqyUcjC4TjJtsfRtev3QKVx2s3eytseOgFCOXeSIK6ZlUDqAjk79jFk1I/dcQmYrv
         HivN3Q1unePe0AHGzYfsb8UGLYIFQQjHZtTpxU6ZqkhZBVArUhC37Qg6sMZajaXMWKeP
         mWGRjLF2x4EeS8kNTLHy6KVXyEq92Q2krKmioIFy8vVe4JjrCGcrkn38+zMAqIC0OYwA
         5OElnYSLc0BxTs5kgM4ji8o3TiB5FUG2YaokewWWSMDV9sZj9MZBoYaHjnZFJk6wFcaC
         KuLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=Stz4O6je;
       spf=pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) smtp.mailfrom=bugzilla-daemon@kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from sin.source.kernel.org (sin.source.kernel.org. [145.40.73.55])
        by gmr-mx.google.com with ESMTPS id dz11-20020a0568306d0b00b006cd090b605dsi199642otb.3.2023.11.03.10.52.08
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Fri, 03 Nov 2023 10:52:08 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@kernel.org designates 145.40.73.55 as permitted sender) client-ip=145.40.73.55;
Received: from smtp.kernel.org (transwarp.subspace.kernel.org [100.75.92.58])
	by sin.source.kernel.org (Postfix) with ESMTP id 825D0CE22EB
	for <kasan-dev@googlegroups.com>; Fri,  3 Nov 2023 17:52:06 +0000 (UTC)
Received: by smtp.kernel.org (Postfix) with ESMTPS id C04DFC433CA
	for <kasan-dev@googlegroups.com>; Fri,  3 Nov 2023 17:52:05 +0000 (UTC)
Received: by aws-us-west-2-korg-bugzilla-1.web.codeaurora.org (Postfix, from userid 48)
	id A76DFC53BD1; Fri,  3 Nov 2023 17:52:05 +0000 (UTC)
From: bugzilla-daemon@kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 218043] KASAN (sw-tags): Clang incorrectly calculates shadow
 memory address
Date: Fri, 03 Nov 2023 17:52:05 +0000
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
X-Bugzilla-Priority: P3
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: 
Message-ID: <bug-218043-199747-4M3OH7Ichq@https.bugzilla.kernel.org/>
In-Reply-To: <bug-218043-199747@https.bugzilla.kernel.org/>
References: <bug-218043-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=Stz4O6je;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=218043

--- Comment #2 from Andrey Konovalov (andreyknvl@gmail.com) ---
Reported: https://github.com/ClangBuiltLinux/linux/issues/1956

FTR, I noticed this bug when investigating why kasan_non_canonical_hook does
not print a report in certain cases. Turned out it bailed out on the addr <
KASAN_SHADOW_OFFSET check, which should not happen if the shadow address is
calculated correctly.

I don't think it's worth it to try applying a workaround for
kasan_non_canonical_hook to handle this buggy Clang behavior though.

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-218043-199747-4M3OH7Ichq%40https.bugzilla.kernel.org/.
