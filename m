Return-Path: <kasan-dev+bncBDLLJZUMQQCBBP44Q7YAKGQEJK3M7TY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3f.google.com (mail-yb1-xb3f.google.com [IPv6:2607:f8b0:4864:20::b3f])
	by mail.lfdr.de (Postfix) with ESMTPS id 05955129F10
	for <lists+kasan-dev@lfdr.de>; Tue, 24 Dec 2019 09:37:21 +0100 (CET)
Received: by mail-yb1-xb3f.google.com with SMTP id 132sf13654305ybb.3
        for <lists+kasan-dev@lfdr.de>; Tue, 24 Dec 2019 00:37:20 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1577176640; cv=pass;
        d=google.com; s=arc-20160816;
        b=MIij3+j3D5eU0tua9hrjXyPfHK+l52ukiGN5pmwx6U7sd6jTP0/R4RaGmTd6sprtuf
         XN148Bjud5+bakXAsCJGpDM84o5g1rTq53RinjfnDilDxcl62l0PcAiJERw1mOBkrUNu
         PCm0eqWHllHu/CdhOE9p4O8lH4peYnoD7774znFl3OujHzdT5LNRliSNXKPAn8YVHvZh
         6PpROv+TPYok4UApYtnVwr6BPXdtuDuvJWaIEn9HCafT+uvWurr8jb5251a/FG0Kod1h
         s+w1j3ZihPkqNSj4X1Zw/Ju83ZXsAV/TZhBUBRsI0QJGXURPf9zYmOhbH0HxP8sYV47z
         QTIQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:to:subject:message-id:date:from
         :reply-to:mime-version:sender:dkim-signature:dkim-signature;
        bh=AnSD2asPQxC2d1dm0U7R1zKpoBuvAcq7bcAZzxgkQ2M=;
        b=DZicHuBcxnZ1x/W3BDHihLILKrbf/qOxKTrSpZauK2hmFNanfkXTlYa5ggjmyeVQd+
         1OCW6wldsKufFtEaq/HuetxWsXsyj03dx1sW1K8Rrp6lf3R4uky0dS93f3eHanwNpcmE
         2Emjdb2vDoMi1OI4rAcN7tKkDhW41kX0xOPMMX+Y7To7wwikecRvL1iVE8GSu3v41GhJ
         N0/YbAtg9cOXVF55nRjbmTmok1fqufyRpjbajLdtVUbHZhb+T6Myf+KQJ95i8HtNrAih
         qUXm3jS24tvclwSVNxfc03DP22EU8Ma5CtDk6jZcqUwse6s/DpLc9n2HNtobBFAl/j77
         r3sw==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VlyE5hkj;
       spf=pass (google.com: domain of am19040@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=am19040@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AnSD2asPQxC2d1dm0U7R1zKpoBuvAcq7bcAZzxgkQ2M=;
        b=gApSRt53QQrbgEj1RBDFMGWmNHAT8auhic38rAmWSFZOdoYSE88S/HIz9EHz1UuCwd
         R3p/X6tVKxvMIBeiw3yp3rALzBQ4rSKQeX1f/DK3fzCx1LhMuIIUD6pVp8XKj+X6CV5o
         LG9U1yXsMVfdwcDWQGUfz+jp/ZJfrWDk3r74f611mIRQC4b8vYvqw6nDITIOUEPyP/ZI
         o+bmh39Ve/im3E5fanHS133rAOq1btgujWSWrUk7d6kvFA+sZrquo4Je6yGQZtTSsiaA
         LH1bU2oCmN47ci/7ZBrWIxKjA5d8P86xdvE8aI7lC+r5h9mVAVC6Wi+OTWk6EMoSHRqb
         AYeQ==
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=gmail.com; s=20161025;
        h=mime-version:reply-to:from:date:message-id:subject:to
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AnSD2asPQxC2d1dm0U7R1zKpoBuvAcq7bcAZzxgkQ2M=;
        b=rCNCifg/GGfs3phW3ZN/bxXVo6X04N/naZbxw2hyws72P1+Je/v7YlozKRiGvR0kwL
         Qmgi9BVMtFSaUgaL7ysrwNBiGTZus3bRqyPS/pjmoBMfsdeZ6460/B1kAqIWH2EUpxHD
         44s7iBMCMy+O+LzBombvW2Te5Wg/pBPoiflAx91woNTneK9311T69PUoSK/FHWCvyt0D
         t3rFjScu254s4f74dp3iqZo+2p5YI4sOMGf3AqJduVJqh/HLZ/4Ql/YFKGfLc13XWonR
         MMxWuPWhW45JWGNNBkxnM41Be5v/M+rCJnsmUQ0oHQPr9oE5tFZcs4E/rislgNuR5Wm8
         yTjQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:mime-version:reply-to:from:date
         :message-id:subject:to:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=AnSD2asPQxC2d1dm0U7R1zKpoBuvAcq7bcAZzxgkQ2M=;
        b=lqRHrlK/LG5LtA3Uh72jvVzI9UY4LV+iUOEasH8h60+2KhugKAi7ChrCgAGPlF25M7
         Ul+pbE+NmHWEbMLbEZQLyGf0++QkyJAStL3Ebqkjtiiqy9/EjLeMhYfvwTEV+kzmKtj0
         tdCso2VW9L5YKP2TQTi0g7lzK5fQH1uEdBcTuj74r02zCxeWhMWQCxM27G4ZSu1jxCP5
         ul/S1TGGrAi1VpduH4/HqJcckoxrXvKV0tHaeZUfk5IPZsoG4GUrsDOV9YhaGEt4sdIl
         S5AuJ9UiSG8fdZWdfAPPlruCOtnqQBakXVVio4p2W2SUs1WzODYpJt7O7VPLTcW52mBT
         GbQA==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWs9oG4liORqXAA2tKjvAE0VnusAvvJOq1xzgt7BePQ0nC6710z
	9NS7aURkZRuAOcaXBkjoSII=
X-Google-Smtp-Source: APXvYqzj7f0rHuEMYTPmsj3HuJEbR0Pl/kDwo97EsLQXFCXyoB5DWHiDiHCoUSLoiVrmu7mRu+eVlg==
X-Received: by 2002:a81:408:: with SMTP id 8mr23430616ywe.88.1577176639943;
        Tue, 24 Dec 2019 00:37:19 -0800 (PST)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a81:5f04:: with SMTP id t4ls2794566ywb.12.gmail; Tue, 24 Dec
 2019 00:37:19 -0800 (PST)
X-Received: by 2002:a81:2847:: with SMTP id o68mr25972438ywo.245.1577176639616;
        Tue, 24 Dec 2019 00:37:19 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1577176639; cv=none;
        d=google.com; s=arc-20160816;
        b=uh2ea+70lU8sdBA7QGL2ZCRuH9lIRVEznMCWhccbaW2X5f5bFrmrHfskvcWStT5wOQ
         7r9VfdgXoSGpisUxI6dOX5/stutsEVuPjW1mU8+Byx1wpXi0mAiOH5zQ9TSVDtvI8Olk
         E2/nsOOpyawRkwr0/gTIQiq2JL8p5DGjDXba/syf49awtyaqJlKuHCpO/MdeUn4dFtk7
         KlsaKJOargwKnuour8FNc6sq2TOT7mnyDElbQGs1qf9L46XjvTpALasTyUo0+oX9VBvk
         pz8xl//915yZM+sR8iAX5Ruz7FFf++Lyb8OhC3HHO/IdatQoJLOwCVLSUfx7d60DOHd7
         j0Dg==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=to:subject:message-id:date:from:reply-to:mime-version
         :dkim-signature;
        bh=LcGU1mt+nAQIi3eKcWZpiy7DqrkNG23tK1MNYV9CB+M=;
        b=acl1jnbQ/xYRqu8RQsfU+zCga3v9k9MYLDLbjA2xSQYR/W3wlzxFtlNmW9kSniQGfm
         hxFBf3XZvoFYAFkbVpMYNzptex6p7gyGzjUHIJ08vF4IY1lWvl8pQINzhszCXXNfalfB
         OYEPD9wH9QgzRlrmPupi+fSKwvQZRTuPB2YYDxrFGVHS7bOnA7aksBQENMpbJ8Kxt1M8
         3QobWD4yBuaaW9PmOgnJoLZ+cbmATZHCeshpWH8FiV33r0oVCOiIuO2tlDVH7S0yFbB0
         fwVn7sjcHDSbXkFSJ2cjtzRn4cqvQWWFw5udTIxtFImmJAXRfLUb+JDaOC/6gLrn1Eus
         UhhQ==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@gmail.com header.s=20161025 header.b=VlyE5hkj;
       spf=pass (google.com: domain of am19040@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) smtp.mailfrom=am19040@gmail.com;
       dmarc=pass (p=NONE sp=QUARANTINE dis=NONE) header.from=gmail.com
Received: from mail-il1-x142.google.com (mail-il1-x142.google.com. [2607:f8b0:4864:20::142])
        by gmr-mx.google.com with ESMTPS id s64si1055050ywf.0.2019.12.24.00.37.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Tue, 24 Dec 2019 00:37:19 -0800 (PST)
Received-SPF: pass (google.com: domain of am19040@gmail.com designates 2607:f8b0:4864:20::142 as permitted sender) client-ip=2607:f8b0:4864:20::142;
Received: by mail-il1-x142.google.com with SMTP id t8so16097328iln.4
        for <kasan-dev@googlegroups.com>; Tue, 24 Dec 2019 00:37:19 -0800 (PST)
X-Received: by 2002:a92:c50e:: with SMTP id r14mr29396039ilg.52.1577176639205;
 Tue, 24 Dec 2019 00:37:19 -0800 (PST)
MIME-Version: 1.0
Received: by 2002:a5e:c244:0:0:0:0:0 with HTTP; Tue, 24 Dec 2019 00:37:18
 -0800 (PST)
Reply-To: bethnatividad9@gmail.com
From: Beth Nat <am19040@gmail.com>
Date: Tue, 24 Dec 2019 08:37:18 +0000
Message-ID: <CAEgaL+akE_7uuR+QBv+=W5npZ3Bg=jguaB4zU63CGVjztQeQyg@mail.gmail.com>
Subject: 
To: undisclosed-recipients:;
Content-Type: text/plain; charset="UTF-8"
X-Original-Sender: am19040@gmail.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@gmail.com header.s=20161025 header.b=VlyE5hkj;       spf=pass
 (google.com: domain of am19040@gmail.com designates 2607:f8b0:4864:20::142 as
 permitted sender) smtp.mailfrom=am19040@gmail.com;       dmarc=pass (p=NONE
 sp=QUARANTINE dis=NONE) header.from=gmail.com
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

How are you today my dear? i saw your profile and it interests me, i
am a Military nurse from USA. Can we be friend? I want to know more
about you.

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/CAEgaL%2BakE_7uuR%2BQBv%2B%3DW5npZ3Bg%3DjguaB4zU63CGVjztQeQyg%40mail.gmail.com.
