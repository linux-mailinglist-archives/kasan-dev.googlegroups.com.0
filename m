Return-Path: <kasan-dev+bncBC24VNFHTMIBBOUEZSEAMGQEXIGMJGA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83d.google.com (mail-qt1-x83d.google.com [IPv6:2607:f8b0:4864:20::83d])
	by mail.lfdr.de (Postfix) with ESMTPS id 52C3F3E8634
	for <lists+kasan-dev@lfdr.de>; Wed, 11 Aug 2021 00:48:27 +0200 (CEST)
Received: by mail-qt1-x83d.google.com with SMTP id w11-20020ac857cb0000b029024e7e455d67sf278486qta.16
        for <lists+kasan-dev@lfdr.de>; Tue, 10 Aug 2021 15:48:27 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1628635706; cv=pass;
        d=google.com; s=arc-20160816;
        b=notURYEEaejDBB85yYGuS6cmufeKzO4eV/9ElRLJrW+tfEILx02okFED2jJoCDwlTc
         KIuYNS0NvPSgN+mmD0Y9IJtAUf1oM9EdrXEbS2jrdbO/oazsfgeDWwe8+b0+U4SoAEKb
         EGAoFgvsB320555ThrvxHyjuzStrwe1744LwvaP3loEG0QpcaE9HgREEXIz+l05w7RVL
         HX+LqA3kG2ljrOGrcvciX0YnNsio4VAHHpTCVXdxuSQuBG0mu1tj6xV9CMYgKRX6C8MS
         T/ZtzsgfWNYUbEOhDEzg2zKv1iuwh/xsPtKbY/uuiOnP+D7PZagH0NKod1CHyhiv3+vG
         sKpA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:auto-submitted
         :references:in-reply-to:message-id:date:subject:to:from:sender
         :dkim-signature;
        bh=7cIVtmrvqR6WylyQzCCl7d6pYwvbv5BDXQ/GsJcM5/E=;
        b=qRjFtWql1dIHJeoz0e8TEiI/wRdNTDGNKyo/5TIVjCtCd79DhtSNk3AvscySkeO4AR
         SB1khqwTZ/IMC8jlR6gvkdOTmAhydhVC6sjnkrCzOdDVvtIOk0VFus/gCgnCkelbDCvg
         VPJhdo75brwQ8zhymvhOfa+Zt4IpOLFiPH2zEZJZ/BVOwhS7ibhTquQzPeCnLkTkhMqJ
         H81sjwHRuNAv71HfF0TlDBElUQLlxDy3Ls/jKkHJThgZ9DcRCtPtB7TVMe3tjxvdmvLg
         rsbWYE/A8pvuyEUIpYMUzV42P8CRfNkaHdC3C1PT1eN2T66PvZZsDDOjEXPJy97GtYzK
         QFSA==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jDijLURe;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:subject:date:message-id:in-reply-to:references
         :auto-submitted:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=7cIVtmrvqR6WylyQzCCl7d6pYwvbv5BDXQ/GsJcM5/E=;
        b=IyIaIJxDZXpUd6jTAhm9OMQWkDXfp8+62szfV16sspgOvArb7RoboMQnNvfgwmk2Zt
         SMPcLg+CG9sg4vqND2YAAIr/lq6A0aIctCt+Xf4CmN9qlSZER/dYshOXs/WPgFa1GNoQ
         BvnrJ7Y1+eFnKjBubu1SVrJmFl3wLOxE5znSJlgojNKKnI+MRDT1tF57HdDNLyZ5BWPp
         tbL3KNjXq/nY/ZY53gvF73ZDuKtGd2zKc2ISZdzDxVNKnqa4JykXZ1KVAiaUv0xgz+88
         jJkQA54gDa1nz8CHn5OiJtgXa3f3r3mGqSr/lWbE1s2nFAgPiQxu+7SSaZPPMQfjVBrN
         NlbA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:subject:date:message-id
         :in-reply-to:references:auto-submitted:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:x-spam-checked-in-group:list-post:list-help
         :list-archive:list-subscribe:list-unsubscribe;
        bh=7cIVtmrvqR6WylyQzCCl7d6pYwvbv5BDXQ/GsJcM5/E=;
        b=IgVzFoBLi1Rm1hSM3mAPybPBa0X4QDNjedsyADhHBjuP/33ZD7hGXZond9ki/+pDfP
         ddysOdeh8j+ksI+YjFFzOZF/tuFjhucHBiuFLPHrN2BArOIqx1CEBQUf9DvR+DJenibn
         uslZ5FUPfTofeRCv1yW7d+2ANCCZ9V+OKAoLzNil/vEo2j45IFzcyQirQfLp/V+WP8pW
         xDR5Ooz6LA7TpZrtc2gqXO3QO/nfpIqGmMsD3FpASNJ5xszbeKS3K2oeFkYMIQ/zeltC
         GDwJ1pfdey3FmKJGINElghaDdA5oJtKo7+Q8QF+3hhQ4P/AX7vd9f0JN/Nfa8jV7sARz
         ZhmQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM532bm4So+tYrBcwn+8SfFVIGRCT+Yd+tji3xQVBrV9aZB1Auq4BB
	ovMVTKkZ8W+nQIljeNE/ru8=
X-Google-Smtp-Source: ABdhPJwBTQPrlsGQPOAQlB3tDBmHoRIzc+Fcwyi1KSXDZtXGRckot8kenVQb0GyIkPXp+hFYTC3XMA==
X-Received: by 2002:a0c:b29b:: with SMTP id r27mr19978030qve.35.1628635706347;
        Tue, 10 Aug 2021 15:48:26 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6214:5004:: with SMTP id jo4ls34268qvb.11.gmail; Tue, 10
 Aug 2021 15:48:26 -0700 (PDT)
X-Received: by 2002:a05:6214:27e4:: with SMTP id jt4mr20191414qvb.45.1628635705949;
        Tue, 10 Aug 2021 15:48:25 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1628635705; cv=none;
        d=google.com; s=arc-20160816;
        b=U7hVjfurWZJxHUqDBsl1Kj7FZr8UvauS7TzmUYYwRUG9oWxjjsx4vkPqSHDFr6bsWz
         9cdXnFi/EnxaVPACwFqrKafOU6TRS/23hi3E7RNmzvsbZN8/t9iu7/Cu9W0UOnI4gwSL
         bYKCdVpv1ia4GHbeMVYJrSVSnQtk3GGqB5TrtFDH/BB6zhsMo7U+HLfE5uGtwHIXGSsn
         fblX/ReA06m7ismGkVo3/5Z/Xx+CRL9p1ejQ56HOJgVzJAyWa/+/dduv0XHa+GJMqFOu
         vVadMyE5dL4O1OQvJjwZ9fSzJgJI/os5UbrLizfCnI/HsI0e9PuULM+fxBul3RfRVLf0
         qJkA==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:auto-submitted:content-transfer-encoding:references
         :in-reply-to:message-id:date:subject:to:from:dkim-signature;
        bh=qjow1vfoBmiQYAuxdEkGwEKX9VV+cH9HMAJPX7HcGqw=;
        b=fvxOmXFQqeO2FqVxC2jVBNzytVz5j6enwZGg93CTl/cTrmrOsFNi8D1/Faej4W6+rH
         SotBvcJM40HSu7dZDVfTYk1yB50vtrZLkKCzZVaGtIX+8OvmxRTqA/hl15ZYqNBuGi1J
         S6WjF1wbTC2NTNC507YOSlGFqQd5ayBJeu6sobjbIst8YD1XlZnxPNzuM6aQkrCYmjOP
         stIlHxOuKk6AeMKsVVEnXA3vLlirTPbLTR8Ib0HCzDp87ZMW2C6ix4DU1+sWjvhNDNlw
         59ThL/3/tPkG537+qNjdTWA7Pk2nfCBlUfiiOPkk2bslHvWLLDSM7tG9a5ABG8W9MJfJ
         t2QQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@kernel.org header.s=k20201202 header.b=jDijLURe;
       spf=pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) smtp.mailfrom=bugzilla-daemon@bugzilla.kernel.org;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=kernel.org
Received: from mail.kernel.org (mail.kernel.org. [198.145.29.99])
        by gmr-mx.google.com with ESMTPS id n2si282660qkp.4.2021.08.10.15.48.25
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-ECDSA-AES128-GCM-SHA256 bits=128/128);
        Tue, 10 Aug 2021 15:48:25 -0700 (PDT)
Received-SPF: pass (google.com: domain of bugzilla-daemon@bugzilla.kernel.org designates 198.145.29.99 as permitted sender) client-ip=198.145.29.99;
Received: by mail.kernel.org (Postfix) with ESMTPS id EAD7A6101E
	for <kasan-dev@googlegroups.com>; Tue, 10 Aug 2021 22:48:24 +0000 (UTC)
Received: by pdx-korg-bugzilla-2.web.codeaurora.org (Postfix, from userid 48)
	id E1CE560E4B; Tue, 10 Aug 2021 22:48:24 +0000 (UTC)
From: bugzilla-daemon@bugzilla.kernel.org
To: kasan-dev@googlegroups.com
Subject: [Bug 211817] KASAN (hw-tags): optimize setting tags for large
 allocations
Date: Tue, 10 Aug 2021 22:48:24 +0000
X-Bugzilla-Reason: CC
X-Bugzilla-Type: changed
X-Bugzilla-Watch-Reason: None
X-Bugzilla-Product: Memory Management
X-Bugzilla-Component: Sanitizers
X-Bugzilla-Version: 2.5
X-Bugzilla-Keywords: 
X-Bugzilla-Severity: normal
X-Bugzilla-Who: andreyknvl@gmail.com
X-Bugzilla-Status: RESOLVED
X-Bugzilla-Resolution: CODE_FIX
X-Bugzilla-Priority: P1
X-Bugzilla-Assigned-To: mm_sanitizers@kernel-bugs.kernel.org
X-Bugzilla-Flags: 
X-Bugzilla-Changed-Fields: bug_status resolution
Message-ID: <bug-211817-199747-JHqkn3qiSE@https.bugzilla.kernel.org/>
In-Reply-To: <bug-211817-199747@https.bugzilla.kernel.org/>
References: <bug-211817-199747@https.bugzilla.kernel.org/>
Content-Type: text/plain; charset="UTF-8"
X-Bugzilla-URL: https://bugzilla.kernel.org/
Auto-Submitted: auto-generated
MIME-Version: 1.0
X-Original-Sender: bugzilla-daemon@bugzilla.kernel.org
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@kernel.org header.s=k20201202 header.b=jDijLURe;       spf=pass
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

https://bugzilla.kernel.org/show_bug.cgi?id=211817

Andrey Konovalov (andreyknvl@gmail.com) changed:

           What    |Removed                     |Added
----------------------------------------------------------------------------
             Status|NEW                         |RESOLVED
         Resolution|---                         |CODE_FIX

--- Comment #3 from Andrey Konovalov (andreyknvl@gmail.com) ---
Implemented with 3d0cca0b02ac ("kasan: speed up mte_set_mem_tag_range").

-- 
You may reply to this email to add a comment.

You are receiving this mail because:
You are on the CC list for the bug.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/bug-211817-199747-JHqkn3qiSE%40https.bugzilla.kernel.org/.
