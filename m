Return-Path: <kasan-dev+bncBAABBVGR6DWAKGQEMTZTJRA@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-qt1-x83e.google.com (mail-qt1-x83e.google.com [IPv6:2607:f8b0:4864:20::83e])
	by mail.lfdr.de (Postfix) with ESMTPS id DAFF4CF27C
	for <lists+kasan-dev@lfdr.de>; Tue,  8 Oct 2019 08:12:37 +0200 (CEST)
Received: by mail-qt1-x83e.google.com with SMTP id s14sf18025186qtn.4
        for <lists+kasan-dev@lfdr.de>; Mon, 07 Oct 2019 23:12:37 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1570515157; cv=pass;
        d=google.com; s=arc-20160816;
        b=J3xIKMuVzI1FNgqVdrIlKrPeIqDEixEXmVv4Kqu+ldrRNfRLBqNwWoXqdg+veL+H0G
         zMzTbpqkQP42tVhFetJU+z0J1J0Gtz86Xf7l90FwGGK66yf6lqUVQne9VkRCinD/eFQn
         3JQXqzscuHc3ew2hAnYkC1AYpSnq3O6SjrfL0wT5kNEpUlWgpqorCWaln8LS45hq1KIL
         Hy6YfHc/LEjofwkkWwNYVw1KBNTrfEtndQ4+l/RpwojrDNwLG0zaLzeWgrDVoYrwnGhZ
         50MjuK5OjjWiHTrcZBeWKNj0B2bEMCqogvRx/A8RmFU7141g0Plqului+iBUbl+PLF3r
         cQww==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:references:in-reply-to
         :message-id:date:subject:cc:to:from:sender:dkim-signature;
        bh=It+8vTchnJ0oD9vlVwq32TJjxzjjXAiEoD7PZ0SS5Jk=;
        b=i9C9Q/1+c/22LFX3qTv+POT0DDL+ufO6MzRPy/fs4YyvSszIS4GOzsCivCAfTGaWZU
         cRVrGHBLB530cGKqAmg0zCttFFKQnLEp5n+rPKtWUseCm+BzjyRmij5Y5Em8XU6jRajB
         HucnaEt3hOvgfjkQneASKvXHzgZzr3r1qEeL07XdOjs//JVHVo7xzhyINacWjHm4vicr
         dMZEJoqWizg00QoPScenW9Nl4B128RpeZ7QCxWIT6Vy6rpFI0yA+khnBxR3VBRx3vGKl
         DkmM1NnHP1g8mo0km9mbWuUtl0o3gFmwX00OYZNq6onqiJj4pTpmqFEJsVhLt3iKUBVi
         uzog==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:in-reply-to:references
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=It+8vTchnJ0oD9vlVwq32TJjxzjjXAiEoD7PZ0SS5Jk=;
        b=naUjS65eeMNkTRfm57xkOSxcFkT+kWJx891tuGWdAbGVl4tyBH5hoE+8ZEJ/QG+XdZ
         rwdMAHQSSWC1wu+kfKiu7CVc348ZpHUVi441ndWdIIR5F+W8kFSMD31ccqbRx5w74vEm
         r4HJCJTkkHaw/NrAaPwhjEsXBJrU5/sgZHM9tMR4xFAnRV73tedCz97nwW5PZasJp4zq
         j05xRCJN8kMLME/SQ6ZBI64gvDpjGLkOQni2NY4dstPwN4E606kfhLOQIYkAIzT3I117
         rXKrQDyLSYeET46umFv1TjaYiMb8Jsj8yg66kEWC61MuvX+pHMSqyjx2EyDXbttDHaG6
         9PVQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :in-reply-to:references:mime-version:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=It+8vTchnJ0oD9vlVwq32TJjxzjjXAiEoD7PZ0SS5Jk=;
        b=BL1uOT5xgL/RiaLygHFscNKtcwSWVJdGeS1MexIu85omLId83RZKeeoOuzAD5S4nP6
         M7Rp+ZKAhryCenN6ja3X6VrKpWzWUrlIB4FjjDjog6lFZrPPGpODL7FZeJf7yAujTicX
         480YpCDLCutpMgd4/oY0KDm5rOQ6JubeWTCzHpW7t4+IJSJ+Wb46A6YcV96mrlC766aT
         od51OV6uHu6S1qS4HJqPuEGlEh+A1jZ+3rbJCC1PIobDMbD3LriSfqAS+3dj3e5hZFSu
         bO8GrF82Mo47PZ/iVYYU0cu+nE56NohVBqaTenoC8x3CoNwcEG6JqTzV2fq+ylRxz1fN
         QD7w==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: APjAAAWf/qELIhdKAPNGQRq9tsOgF9irzWrE1ozSKhe6m10MZiCsXaVT
	11njBEAQ9OUpnDNMYELf7m4=
X-Google-Smtp-Source: APXvYqyo8+MZ7pbQNNmzArecnhWTFZC2XWxmui4J2Qr9h37wTnfcafnxUS4V2/beL8Wl++qYqJrsiA==
X-Received: by 2002:ac8:32ec:: with SMTP id a41mr33946120qtb.18.1570515156962;
        Mon, 07 Oct 2019 23:12:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a0c:aac8:: with SMTP id g8ls415180qvb.10.gmail; Mon, 07 Oct
 2019 23:12:36 -0700 (PDT)
X-Received: by 2002:ad4:4772:: with SMTP id d18mr31516029qvx.100.1570515156544;
        Mon, 07 Oct 2019 23:12:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1570515156; cv=none;
        d=google.com; s=arc-20160816;
        b=wtQJeNV/WtydA2qOof9LCl/NGAKReZtzYV9LLLfhwEsLjWeXeS6n3FN/y1UrqE6FJJ
         jQGOosJWCF95wdYvY8QpBIaZfDdijqqBlgLsa/IJqQ5rl27Z5L5z1Dkeg8xf78aakVsw
         GsCPZyVxq8oP7hZnjIofUOBAtz/FQejNV6JHDT8kiTDB+tk53IN1g1fFld7IwyPjUT+g
         VOMf+CxS0WECiPL9N7bRXu2Ol4+IF7vtPWHiUPrNLh9hI+J2rC3UYwieZ6ygwQaZs9IP
         MlphWSrARjp7/6UnEV1J5KXpywvgOOM6G0M7Gk7S4AQ5pB+o8Lra834TGLHJ8/ROaSIH
         hR0w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=mime-version:references:in-reply-to:message-id:date:subject:cc:to
         :from;
        bh=yRjuma5UGlXgnJJhwq9b6CPNlwqZXPQmv0iTUFFsrQc=;
        b=bH66/+nTk1I5VcX5cr1VawjgSdD5eFYx18SBOStXcCCBWs0IjN85IotgaogMAQhuhh
         mj8UH4Tmv5ElOOHBG6Wp32gNq4TTT0TcGnsKp8NfzhTzpwLQJq6dl+yL3fBHBY3N6ecR
         JUhkCdUXMd8GGxnAWb6BPD+T+EYQblaWrUXcy+UP3J2/RDsxoiJXfwjtSXmsB1pHPFKh
         CmzjCSvm+ZfYxI/cCr4YdSKwE60nK9PLOX4apy1kt3UpkrsXEkKJOH+KGKvG7p22Ay19
         SM72JrzYVgd2+S558vYW8poR1ap9iDArPaCTAw3BDP3VbJ2hvjfd9Edgvct1dz9ssP0S
         rLkw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) smtp.mailfrom=nickhu@andestech.com
Received: from ATCSQR.andestech.com (59-120-53-16.HINET-IP.hinet.net. [59.120.53.16])
        by gmr-mx.google.com with ESMTPS id o8si546271qtk.0.2019.10.07.23.12.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_2 cipher=ECDHE-RSA-AES128-GCM-SHA256 bits=128/128);
        Mon, 07 Oct 2019 23:12:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as permitted sender) client-ip=59.120.53.16;
Received: from mail.andestech.com (atcpcs16.andestech.com [10.0.1.222])
	by ATCSQR.andestech.com with ESMTP id x985uS4f075344;
	Tue, 8 Oct 2019 13:56:28 +0800 (GMT-8)
	(envelope-from nickhu@andestech.com)
Received: from atcsqa06.andestech.com (10.0.15.65) by ATCPCS16.andestech.com
 (10.0.1.222) with Microsoft SMTP Server id 14.3.123.3; Tue, 8 Oct 2019
 14:12:20 +0800
From: Nick Hu <nickhu@andestech.com>
To: <alankao@andestech.com>, <paul.walmsley@sifive.com>, <palmer@sifive.com>,
        <aou@eecs.berkeley.edu>, <aryabinin@virtuozzo.com>,
        <glider@google.com>, <dvyukov@google.com>, <corbet@lwn.net>,
        <alexios.zavras@intel.com>, <allison@lohutok.net>,
        <Anup.Patel@wdc.com>, <tglx@linutronix.de>,
        <gregkh@linuxfoundation.org>, <atish.patra@wdc.com>,
        <kstewart@linuxfoundation.org>, <linux-doc@vger.kernel.org>,
        <linux-riscv@lists.infradead.org>, <linux-kernel@vger.kernel.org>,
        <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>
CC: Nick Hu <nickhu@andestech.com>
Subject: [PATCH v3 3/3] kasan: Add riscv to KASAN documentation.
Date: Tue, 8 Oct 2019 14:11:53 +0800
Message-ID: <8f3c66f3f24450b21b749a5e6e6eabf066632ac9.1570514545.git.nickhu@andestech.com>
X-Mailer: git-send-email 2.17.0
In-Reply-To: <cover.1570514544.git.nickhu@andestech.com>
References: <cover.1570514544.git.nickhu@andestech.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-Originating-IP: [10.0.15.65]
X-DNSRBL: 
X-MAIL: ATCSQR.andestech.com x985uS4f075344
X-Original-Sender: nickhu@andestech.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of nickhu@andestech.com designates 59.120.53.16 as
 permitted sender) smtp.mailfrom=nickhu@andestech.com
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

Add riscv to the KASAN documentation to mention that riscv
is supporting generic kasan now.

Signed-off-by: Nick Hu <nickhu@andestech.com>
---
 Documentation/dev-tools/kasan.rst | 4 ++--
 1 file changed, 2 insertions(+), 2 deletions(-)

diff --git a/Documentation/dev-tools/kasan.rst b/Documentation/dev-tools/kasan.rst
index b72d07d70239..34fbb7212cbc 100644
--- a/Documentation/dev-tools/kasan.rst
+++ b/Documentation/dev-tools/kasan.rst
@@ -21,8 +21,8 @@ global variables yet.
 
 Tag-based KASAN is only supported in Clang and requires version 7.0.0 or later.
 
-Currently generic KASAN is supported for the x86_64, arm64, xtensa and s390
-architectures, and tag-based KASAN is supported only for arm64.
+Currently generic KASAN is supported for the x86_64, arm64, xtensa, s390 and
+riscv architectures, and tag-based KASAN is supported only for arm64.
 
 Usage
 -----
-- 
2.17.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/8f3c66f3f24450b21b749a5e6e6eabf066632ac9.1570514545.git.nickhu%40andestech.com.
