Return-Path: <kasan-dev+bncBAABBJNNZ6HQMGQEUEOHSDY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pj1-x103c.google.com (mail-pj1-x103c.google.com [IPv6:2607:f8b0:4864:20::103c])
	by mail.lfdr.de (Postfix) with ESMTPS id 71F9C49F873
	for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 12:42:31 +0100 (CET)
Received: by mail-pj1-x103c.google.com with SMTP id x4-20020a17090ab00400b001b58c484826sf6133743pjq.0
        for <lists+kasan-dev@lfdr.de>; Fri, 28 Jan 2022 03:42:31 -0800 (PST)
ARC-Seal: i=2; a=rsa-sha256; t=1643370149; cv=pass;
        d=google.com; s=arc-20160816;
        b=UH6yzRo7QXhLu+E3tdPWHY/txtQUKEjpndmQyNmDZAiOwEtxkIHL0+CCSM0nypicFU
         gk/2Q+KxV2kecn0bHFLC3kQR2tLSuTH5z7STV8GCH9kZeh6FKT2JmOlUDpR4TE7qUYNs
         VpMmrRMifGtQ7p5mtg1R3wJIu+rl0V0aC85c9IyFn72bRxKyjJbESgCfgO6scZd6LgtO
         F6Y9bzlbQej84EXuFFusMuRrTWl826gVyxQqisHi/4OwSrZHQAgGtZ3T8f3GwuZfMqb9
         QfVbkoNS5w39trtOdedDcHwz4CUi3CBro6XMqKRljVxN109ihYt0QmU0ygO7GzD7DIao
         ziGg==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:references:in-reply-to:message-id
         :date:subject:cc:to:from:mime-version:sender:dkim-signature;
        bh=wp6I+zxXRJ0/lQRSb2L4yp4AMyrU4VYlt5ooeZXj6yw=;
        b=nhcn173rlurMYr0yojNYd6+eufknV7Vzr01mHQdZn/jCEvDn+QqE5ZMYW5zaAm9Wgc
         F3HlclqV+ix2+dbuzTnDZrzSRTCEwQBzWmH733TGvfHRaPI4TAuYxRnRBdYGQaC2khKR
         YKUR08lIPZuByLXu8bCxfHWTi+F5C+YGt1Mj1UN8fF2sqvHl2t2ijtwrEdfmhWw7gcjI
         6J5vM8SwMvkQF2opjS+2WFPPsm5aa9pYADvF8eshcCMf/j/ox8ZCtupoeq7gZ6lBkMli
         YbWn1FwyOC728Lf7L6aKouFfRr784Z0dux+YebR9QdbDmq0/cMnZogu5nUFHU1xaLRGM
         xxtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20210112;
        h=sender:mime-version:from:to:cc:subject:date:message-id:in-reply-to
         :references:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wp6I+zxXRJ0/lQRSb2L4yp4AMyrU4VYlt5ooeZXj6yw=;
        b=RPt7b2euvjgHPxNG2fpIh7tryr5XF83b9JqjMrDLzec5acnKxzPaSSf1f+Zb0LJfhR
         Mf9z8JrY3AkONpDv5RpQveF5MdnCjlKIpEyK/+EJmyO0HvBUM45O7B9EkTSGeahbKGLV
         +uqjc1UGtwtNBPl0/8OJxnHQZFEGLSLqfJN79EdhXMW29zZTJeyvkrHWMXDPmkleq0V8
         2G07aDsUjxR7jX/7rZuGYkwVOcGGA3tuz+qibjH0hklE8iyTowWk6O/gg8fH2tuXGXZu
         7Q5QObaab6X5ZH6+vS/mSFF13nkrNTR+cngDsPc/2NxNB7O9pgBlVHCLGFcCZOhaN6Hh
         JqrQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20210112;
        h=sender:x-gm-message-state:mime-version:from:to:cc:subject:date
         :message-id:in-reply-to:references:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wp6I+zxXRJ0/lQRSb2L4yp4AMyrU4VYlt5ooeZXj6yw=;
        b=O7nPB/GFSRIiiKx9GaSZHq1ynXPREEmmSqBzRtwaW3Xl3g9/U/gOO2QY6bu2q4+RRh
         mN3PCCbngKSfQW/c/wjg/szEjDVO+DhSOWABTe52PniYgVyQEepBHTPL+D9Ui+K/0Y14
         PNFSF6+PyBGuTt/VO+llrf7L31i3QPbTprz6amXyOu8oKD65KlEhKuwA/yoKct5yuOoq
         E0DXExgzs8oUeqdzcOWSWREnY7vw9ntGQ95MIQS6OZ5Io1aH5mqGi46WbCIbiM5Zl+2m
         FFXhoTGAGIlRWktdfMXm9ywnDlKfuaQq9pbuxz3EDl9qFvPjaebEUwDv+AvRxWjtSy/y
         SreQ==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM533TvYcuCWOnmNDSTxo1DtGxB3mCKMgEZJ41gQrvSVA+hJDEhB8J
	8jFc97vB/kpHob/SdQ45JKE=
X-Google-Smtp-Source: ABdhPJxjf3dZqn37+R7dNCobB4qsN58xYSrvlAfWdeu5tTVgxxGQ7Ut7SbajBCArR1uMKIUfNWnaIQ==
X-Received: by 2002:a17:902:8c81:: with SMTP id t1mr8157087plo.16.1643370149633;
        Fri, 28 Jan 2022 03:42:29 -0800 (PST)
MIME-Version: 1.0
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:13a9:: with SMTP id t41ls3681510pfg.10.gmail; Fri,
 28 Jan 2022 03:42:29 -0800 (PST)
X-Received: by 2002:a62:e116:: with SMTP id q22mr7754231pfh.48.1643370149125;
        Fri, 28 Jan 2022 03:42:29 -0800 (PST)
ARC-Seal: i=1; a=rsa-sha256; t=1643370149; cv=none;
        d=google.com; s=arc-20160816;
        b=uUCXIn81NZT2SGE6V/VsVx8UU99vnRZ/NznW1Tw0VFaZQopjkES5uiYiDGmO3Q5Hb6
         IpliibH9oGaLVOCJWlhbdBNe5mfeD7+WNcBKkuJ90M4aUASGZBWmILRtqUVX10HgzUmc
         U9TdJ8gvHaOTdvoIltrZGBzkdKv40S3gK563skPZvCP4Wkg0piQDfkG6jLYgmpfOdXjw
         vqIxw6VkoJ1k/B2iDoW1JDNNaRzz9pIELXwiIjZ6LXEcsxhOjkBlNXmSAZdZDerf8f+6
         IGYC+IoFt3KgHRoTk+uq86ONfUSfCMIyxEBsTBRlKOEdbaLE89UiJwsJOiz3T1yytztp
         Uk/w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=references:in-reply-to:message-id:date:subject:cc:to:from;
        bh=L/bNPbrudTbLAD1sIDDMx75HC9Zf3hW2kRraUNSjlms=;
        b=ob9/Z8qUO1rWGbbTmgbulxsd5TRxheFRGN5mJWpdjU2RdLEXq8BJ0h3l5oC1EwK5xs
         m2SpvPAMiv74DPDMNoWzAXCjrV++nTMmxk7iCIjyjHOKQgevZ6eJOqm9u28FGqroAn/S
         L3Ewqqdfnzf3UTt2R/yXv9FhYF9Oux8EbiK1k6DJWMjwPQwbrpjlkPTGKxsw47rSBABT
         icCUCHdcdPOsSt+/GUPOT5v5oRMk7NQp+ZytcfUjd3xFJqYVNJUZfYhw2WD9sEIqRC4H
         B4bXcabgPAoP5MPHy6UQvj4GeYc0RZVt7haFivd1js+PzOcQ2BiapLNF9VozrU9y8g44
         LH9g==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Received: from loongson.cn (mail.loongson.cn. [114.242.206.163])
        by gmr-mx.google.com with ESMTP id c6si270780plg.9.2022.01.28.03.42.28
        for <kasan-dev@googlegroups.com>;
        Fri, 28 Jan 2022 03:42:29 -0800 (PST)
Received-SPF: pass (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as permitted sender) client-ip=114.242.206.163;
Received: from linux.localdomain (unknown [113.200.148.30])
	by mail.loongson.cn (Coremail) with SMTP id AQAAf9Dxb+Kh1vNhREgFAA--.17556S4;
	Fri, 28 Jan 2022 19:42:27 +0800 (CST)
From: Tiezhu Yang <yangtiezhu@loongson.cn>
To: Baoquan He <bhe@redhat.com>,
	Jonathan Corbet <corbet@lwn.net>,
	Andrew Morton <akpm@linux-foundation.org>,
	Peter Zijlstra <peterz@infradead.org>,
	Marco Elver <elver@google.com>
Cc: kexec@lists.infradead.org,
	linux-doc@vger.kernel.org,
	kasan-dev@googlegroups.com,
	linux-mm@kvack.org,
	linux-kernel@vger.kernel.org
Subject: [PATCH 2/5] docs: kdump: add scp sample to write out the dump file
Date: Fri, 28 Jan 2022 19:42:22 +0800
Message-Id: <1643370145-26831-3-git-send-email-yangtiezhu@loongson.cn>
X-Mailer: git-send-email 2.1.0
In-Reply-To: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
References: <1643370145-26831-1-git-send-email-yangtiezhu@loongson.cn>
X-CM-TRANSID: AQAAf9Dxb+Kh1vNhREgFAA--.17556S4
X-Coremail-Antispam: 1UD129KBjvdXoWrKFyktrW7AFW5ur4kuF18AFb_yoW3tFg_Ka
	97WF4kXF17J340qr17tFWDZF1fZw45uayF9rs7Jr4UA3y3Xan8JFyvvFyDAFyUWFnY9ryf
	Wa95XryxArnFgjkaLaAFLSUrUUUUUb8apTn2vfkv8UJUUUU8Yxn0WfASr-VFAUDa7-sFnT
	9fnUUIcSsGvfJTRUUUbqxYjsxI4VWxJwAYFVCjjxCrM7AC8VAFwI0_Wr0E3s1l1xkIjI8I
	6I8E6xAIw20EY4v20xvaj40_Wr0E3s1l1IIY67AEw4v_Jr0_Jr4l82xGYIkIc2x26280x7
	IE14v26r15M28IrcIa0xkI8VCY1x0267AKxVW8JVW5JwA2ocxC64kIII0Yj41l84x0c7CE
	w4AK67xGY2AK021l84ACjcxK6xIIjxv20xvE14v26r1I6r4UM28EF7xvwVC0I7IYx2IY6x
	kF7I0E14v26r4j6F4UM28EF7xvwVC2z280aVAFwI0_GcCE3s1l84ACjcxK6I8E87Iv6xkF
	7I0E14v26rxl6s0DM2AIxVAIcxkEcVAq07x20xvEncxIr21l5I8CrVACY4xI64kE6c02F4
	0Ex7xfMcIj6xIIjxv20xvE14v26r1j6r18McIj6I8E87Iv67AKxVW8JVWxJwAm72CE4IkC
	6x0Yz7v_Jr0_Gr1lF7xvr2IYc2Ij64vIr41lFIxGxcIEc7CjxVA2Y2ka0xkIwI1lc2xSY4
	AK67AK6r4kMxAIw28IcxkI7VAKI48JMxC20s026xCaFVCjc4AY6r1j6r4UMI8I3I0E5I8C
	rVAFwI0_Jr0_Jr4lx2IqxVCjr7xvwVAFwI0_JrI_JrWlx4CE17CEb7AF67AKxVWUtVW8Zw
	CIc40Y0x0EwIxGrwCI42IY6xIIjxv20xvE14v26r1j6r1xMIIF0xvE2Ix0cI8IcVCY1x02
	67AKxVW8JVWxJwCI42IY6xAIw20EY4v20xvaj40_Jr0_JF4lIxAIcVC2z280aVAFwI0_Jr
	0_Gr1lIxAIcVC2z280aVCY1x0267AKxVW8JVW8JrUvcSsGvfC2KfnxnUUI43ZEXa7IU0du
	ctUUUUU==
X-CM-SenderInfo: p1dqw3xlh2x3gn0dqz5rrqw2lrqou0/
X-Original-Sender: yangtiezhu@loongson.cn
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of yangtiezhu@loongson.cn designates 114.242.206.163 as
 permitted sender) smtp.mailfrom=yangtiezhu@loongson.cn
Content-Type: text/plain; charset="UTF-8"
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

Except cp and makedumpfile, add scp sample to write out the dump file.

Signed-off-by: Tiezhu Yang <yangtiezhu@loongson.cn>
---
 Documentation/admin-guide/kdump/kdump.rst | 4 ++++
 1 file changed, 4 insertions(+)

diff --git a/Documentation/admin-guide/kdump/kdump.rst b/Documentation/admin-guide/kdump/kdump.rst
index d187df2..a748e7e 100644
--- a/Documentation/admin-guide/kdump/kdump.rst
+++ b/Documentation/admin-guide/kdump/kdump.rst
@@ -533,6 +533,10 @@ the following command::
 
    cp /proc/vmcore <dump-file>
 
+or use scp to write out the dump file between hosts on a network, e.g::
+
+   scp /proc/vmcore remote_username@remote_ip:<dump-file>
+
 You can also use makedumpfile utility to write out the dump file
 with specified options to filter out unwanted contents, e.g::
 
-- 
2.1.0

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/1643370145-26831-3-git-send-email-yangtiezhu%40loongson.cn.
