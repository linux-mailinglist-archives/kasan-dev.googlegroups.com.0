Return-Path: <kasan-dev+bncBDGPTM5BQUDRBM7KRX5AKGQELEGBJDI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-io1-xd37.google.com (mail-io1-xd37.google.com [IPv6:2607:f8b0:4864:20::d37])
	by mail.lfdr.de (Postfix) with ESMTPS id 3387524F39E
	for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 10:07:17 +0200 (CEST)
Received: by mail-io1-xd37.google.com with SMTP id q5sf5568432ion.12
        for <lists+kasan-dev@lfdr.de>; Mon, 24 Aug 2020 01:07:17 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1598256436; cv=pass;
        d=google.com; s=arc-20160816;
        b=ylVmV4VR38BpYlSAQUS4n5mMh2g9PI3f7REb/6DE+8WV2fqI/ZuaxbraFSJihwDrId
         4Bbmbg174v9CgDyU3ffB0WPg6kzm8VfoHDU+kqnSwQHdypHDP+uIH7TjYh/q1ud678eC
         XG45/ZMT3KrwW9jPkuSr4DAZJLf9KlwOm5c32goG0rkrfIwQJ3eYUkhWhbnmjxKaZDh3
         S9IigSsbOk1pwPU//VEJX0boJWIFAw8kayJsim1Ofk54fU5hKUI+OQfIX65ZJ8A990pj
         n5AWJ64B4TraF+Qlv3Tn5B3sylmDpQjs5Gc8LDvVMq2Xrig7DVDncmgmBSZJtBbLqL/X
         lK8g==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:mime-version:message-id:date
         :subject:cc:to:from:sender:dkim-signature;
        bh=c3Y+rphHLIGFhrJfvfBM1w+W6A7kihKHwfHXA7q24Kg=;
        b=yY9n9OuUYcfqHhp6sEgiJ4Rul9shUDPXLiyxsVwo71JS4verzJGMgrPO+HRJYvQoUX
         DF4nDyeagb159KXeCrqZ107rNzWTHvUF4rwRzGk3cNEDRXRjlMWwvBhf6GaiTk5nZjyD
         XjIE61tDb5pqUk1MJzKlbQDoeBfcXnx4B23YCBuZTqZn/sS/A0aycUBq3vFahpu9/1SN
         pUxALmDoiqc/I1VZufVgaJoJb+lIaAXaPhUL6Gmv7xGi9tLaPwtV5ZQrGLzbW2Op5grp
         wkJX1JmpFQfosaJq8OUUJ8eq65H5WaYdBOrAN8A5mZbquEzYEUvArqylpXhpgvLYOyU7
         oY0w==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="VHJf/G5t";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:subject:date:message-id:mime-version
         :x-original-sender:x-original-authentication-results:precedence
         :mailing-list:list-id:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=c3Y+rphHLIGFhrJfvfBM1w+W6A7kihKHwfHXA7q24Kg=;
        b=DjXoHJ6PgEJwQ5EduaphjCFgQaYhp3Z6pZH8ZIEBUFeAgGV+L+udcXixJf9Ku5cyFU
         d5tenL+AmZviLota5nmSK7trNFi6ZdguwVltBZyeyKE6juKCGY8bPdlinHzgr8B6RLjQ
         fElm2NPry7gGwL0In0aSfJ8XqCujKmWqBxHqvcf29DsBjMV7sjVqwLR7+LzASKpDo3xt
         N9CHky87uD0Pj+8yPccvXolbKTuIiDChGrDbSKLjGlptKSFYhB878Toh36NI4EiSqF3E
         8wZ7vsTytyy+cPusaNSXebJNoRnl8svKWYRXT9IOFTGnweVR/YRbpbPfBZkEsucP6VaN
         Vscw==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:subject:date:message-id
         :mime-version:x-original-sender:x-original-authentication-results
         :precedence:mailing-list:list-id:x-spam-checked-in-group:list-post
         :list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=c3Y+rphHLIGFhrJfvfBM1w+W6A7kihKHwfHXA7q24Kg=;
        b=OcVAgVWRklsWlYNdpW+Xa0sCRhNIT/zHq2XRptJi/71t2m7+YZbLZ0qVrvfVGsFNFX
         UGMYYkNwah95CrpUDEzAqelO7e1GuMGlNmWRUa7DjDpny5NrjmurBfLOmA5Q0CPsPeS8
         OdCe/SuW1pCoNVFDjjnP4U52RBlVlkmzWnMUnAeOHiWdHxHQnyffBmMtjr4hr4wwvEpd
         JV/nJzYaCHJYiI2Ju9yTv/579NgfY6hHKou74jNd2KjS+uD8zPsjrVVg09hl5qR638co
         OtqDGFCTI5yEDzObgnKHFvftrAleDSZIYvcssL8P5yz5KNFxMxK45IceegtP4NxZK+J5
         7qWg==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531NQtdWT0iYrGwrlEtUM0iEnk3k8C+Td62GalQ7ulnvtUHbELCh
	OUbgmm48xRGf6R+26y6gLUA=
X-Google-Smtp-Source: ABdhPJwvfbtzg/ZGq3PjGy2QbYEZlHmkrWtRP7qdWepS4X6zTPahrueQnU6ZrKNcVs7/9FgmWlXt2Q==
X-Received: by 2002:a5d:9bd5:: with SMTP id d21mr3816598ion.68.1598256435810;
        Mon, 24 Aug 2020 01:07:15 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a92:a1d2:: with SMTP id b79ls1080995ill.0.gmail; Mon, 24 Aug
 2020 01:07:14 -0700 (PDT)
X-Received: by 2002:a92:1901:: with SMTP id 1mr3763444ilz.283.1598256433983;
        Mon, 24 Aug 2020 01:07:13 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1598256433; cv=none;
        d=google.com; s=arc-20160816;
        b=H71fTjoLKVJLold5FI7pe7hBC9wmI+dZPVocKuK6FF2PE7YAyGG6dJAYx1n/uBd5RZ
         cPuy0sQpjnCEumCTZHjl04ORMWkGJAl3X5rH6fyel9/YINBlAWTF+FaiALW+y/ISpLXB
         6DAg2Q2p3WoeOJpSWe3RAEpmm6/xAWkrCEopS/na/S3KP6/dzRsyKV59nAC5Hz6JJllc
         5tquEeFJ+kxlznegAODEUXSVcVnymo9Ub34VOzNcow4ytLZUcV/q1uKwFzBSs4m82UVf
         WvEtpy0kkOytoYgLv4UpiuS/t+MUTYCDFTgpguA+EWdyM99Tdf3j/VQebqExdWWk1quM
         8G4w==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=content-transfer-encoding:mime-version:message-id:date:subject:cc
         :to:from:dkim-signature;
        bh=Ws+o5UOYVh6zo1fhqEVNgTGjFEJeI4HICegFEkqKmwA=;
        b=tdDaNgE3aeehu+8+LLaXhNd8HGnRtkdxuBjhVY0nQBWVm7zXnUelKiNInYWJ6zEe3J
         U9wLXx8WZCqtlB6XqiMxMQWMn99Co1xFpUSaO09JHI2HE+IF7A1ZOF3AKt5+2OoF5ukP
         gbjrI0WD4cjo80AhU8QXh7so3WYaLa+7SLkX3aRyBlYhJ8OuZmjoe+ExhQAPBYSzGUY1
         WEbcpSXfKqnPL88gaTP/1mHa34z0lA61/KYdO6umxkXi/YtDKHTFXA3uv8S5xCF0+QcA
         tLjuGds0OSJtC7eu/y3cs9A7/iKE0wT6eD8fFL1UuIDRYCUiKucbLSIsBv5t6AAqHy98
         YpGw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       dkim=pass header.i=@mediatek.com header.s=dk header.b="VHJf/G5t";
       spf=pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
Received: from mailgw01.mediatek.com ([210.61.82.183])
        by gmr-mx.google.com with ESMTP id o74si472433ili.4.2020.08.24.01.07.13
        for <kasan-dev@googlegroups.com>;
        Mon, 24 Aug 2020 01:07:13 -0700 (PDT)
Received-SPF: pass (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as permitted sender) client-ip=210.61.82.183;
X-UUID: 65827033c7fa4ed9be0c8c45bc777b51-20200824
X-UUID: 65827033c7fa4ed9be0c8c45bc777b51-20200824
Received: from mtkcas07.mediatek.inc [(172.21.101.84)] by mailgw01.mediatek.com
	(envelope-from <walter-zh.wu@mediatek.com>)
	(Cellopoint E-mail Firewall v4.1.10 Build 0809 with TLS)
	with ESMTP id 1135189248; Mon, 24 Aug 2020 16:07:10 +0800
Received: from MTKCAS06.mediatek.inc (172.21.101.30) by
 mtkmbs01n2.mediatek.inc (172.21.101.79) with Microsoft SMTP Server (TLS) id
 15.0.1497.2; Mon, 24 Aug 2020 16:07:06 +0800
Received: from mtksdccf07.mediatek.inc (172.21.84.99) by MTKCAS06.mediatek.inc
 (172.21.101.73) with Microsoft SMTP Server id 15.0.1497.2 via Frontend
 Transport; Mon, 24 Aug 2020 16:07:06 +0800
From: Walter Wu <walter-zh.wu@mediatek.com>
To: Marco Elver <elver@google.com>, Andrey Ryabinin <aryabinin@virtuozzo.com>,
	Alexander Potapenko <glider@google.com>, Dmitry Vyukov <dvyukov@google.com>,
	Matthias Brugger <matthias.bgg@gmail.com>, John Stultz
	<john.stultz@linaro.org>, Stephen Boyd <sboyd@kernel.org>, Andrew Morton
	<akpm@linux-foundation.org>, Tejun Heo <tj@kernel.org>, Lai Jiangshan
	<jiangshanlai@gmail.com>
CC: <kasan-dev@googlegroups.com>, <linux-mm@kvack.org>,
	<linux-kernel@vger.kernel.org>, <linux-arm-kernel@lists.infradead.org>,
	wsd_upstream <wsd_upstream@mediatek.com>,
	<linux-mediatek@lists.infradead.org>, Walter Wu <walter-zh.wu@mediatek.com>
Subject: [PATCH v2 0/6] kasan: add workqueue and timer stack for generic KASAN
Date: Mon, 24 Aug 2020 16:07:06 +0800
Message-ID: <20200824080706.24704-1-walter-zh.wu@mediatek.com>
X-Mailer: git-send-email 2.18.0
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-TM-SNTS-SMTP: 3CA77E6D371981748F1B9D271F7149CE6182270AF73BF62DA9C780BF27EE73342000:8
X-MTK: N
X-Original-Sender: walter-zh.wu@mediatek.com
X-Original-Authentication-Results: gmr-mx.google.com;       dkim=pass
 header.i=@mediatek.com header.s=dk header.b="VHJf/G5t";       spf=pass
 (google.com: domain of walter-zh.wu@mediatek.com designates 210.61.82.183 as
 permitted sender) smtp.mailfrom=walter-zh.wu@mediatek.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=mediatek.com
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

Syzbot reports many UAF issues for workqueue or timer, see [1] and [2].
In some of these access/allocation happened in process_one_work(),
we see the free stack is useless in KASAN report, it doesn't help
programmers to solve UAF on workqueue. The same may stand for times.

This patchset improves KASAN reports by making them to have workqueue
queueing stack and timer queueing stack information. It is useful for
programmers to solve use-after-free or double-free memory issue.

Generic KASAN will record the last two workqueue and timer stacks,
print them in KASAN report. It is only suitable for generic KASAN.

[1]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22+process_one_work
[2]https://groups.google.com/g/syzkaller-bugs/search?q=%22use-after-free%22%20expire_timers
[3]https://bugzilla.kernel.org/show_bug.cgi?id=198437

Walter Wu (6):
timer: kasan: record timer stack
workqueue: kasan: record workqueue stack
kasan: print timer and workqueue stack
lib/test_kasan.c: add timer test case
lib/test_kasan.c: add workqueue test case
kasan: update documentation for generic kasan

---

Changes since v1:
- Thanks for Marco and Thomas suggestion.
- Remove unnecessary code and fix commit log
- reuse kasan_record_aux_stack() and aux_stack
  to record timer and workqueue stack.
- change the aux stack title for common name.

---

Documentation/dev-tools/kasan.rst |  4 ++--
kernel/time/timer.c               |  3 +++
kernel/workqueue.c                |  3 +++
lib/test_kasan.c                  | 54 ++++++++++++++++++++++++++++++++++++++++++++++++++++++
mm/kasan/report.c                 |  4 ++--
5 files changed, 64 insertions(+), 4 deletions(-)

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20200824080706.24704-1-walter-zh.wu%40mediatek.com.
